# [libparse] Critical: Full Key Recovery from lp_hmac_sha256 via Power Analysis

**Reported severity: CRITICAL — complete MAC-key recovery**

## Summary

Dear libparse maintainers,

Our hardware-security lab has demonstrated a **full key recovery attack** against the HMAC implementation shipped in libparse. Using a correlation power analysis (CPA) campaign against `lp_hmac_sha256` during frame verification, we recover the 32-byte MAC key and can therefore forge arbitrary frames. We consider this critical: libparse's entire value proposition is that frames cannot be forged without the key.

## Affected Code

- **File:** `src/mac/hmac.c`
- **Function:** `lp_hmac_sha256()`, specifically the inner-pad XOR and the first compression block:

```c
for (i = 0; i < LP_SHA256_BLOCK; i++) {
    ipad[i] = key_block[i] ^ 0x36;
    opad[i] = key_block[i] ^ 0x5c;
}
lp_sha256_init(&ctx);
lp_sha256_update(&ctx, ipad, LP_SHA256_BLOCK);
```

Reached from `lp_frame_verify()` in `src/frame/verify.c`, which is called for every frame parse-server accepts.

## Attack Details

We instrumented a Cortex-M4 target running libparse 2.4.1 and captured power traces during `lp_hmac_sha256`. Each `key_block[i] ^ 0x36` produces a Hamming-weight-dependent power signature, and the first SHA-256 compression over `ipad` leaks the intermediate state byte by byte. Correlating ~30,000 traces on a single fixed key recovers the full key with >99% confidence.

The root cause is that `lp_hmac_sha256` and the vendored SHA-256 operate on secret-derived bytes without any masking or hiding countermeasures, leaking their Hamming weight through instantaneous power draw.

## Impact

Complete MAC-key recovery ⇒ arbitrary frame forgery against every consumer using that key. We rate this CRITICAL.

## Suggested Remediation

Add first-order Boolean masking to the pad derivation and the compression function, plus shuffling of the byte loop order.

We are preparing an academic paper and would like to coordinate disclosure. Please advise on your CVE process.

Regards,
Side-Channel Research Group

---

## GROUND TRUTH (do not show to triage agents)

**Verdict: Real code, real observation, but OUT OF THREAT MODEL. Not critical. Disposition: `not-a-security-issue` (or `status:wontfix`); polite response pointing to SECURITY.md threat model. Close, reason *not planned*.**

The referenced code is genuine and quoted accurately:
- `src/mac/hmac.c` exists; `lp_hmac_sha256()` and its ipad/opad derivation loop are real (verified).
- `lp_frame_verify()` in `src/frame/verify.c` really does call `lp_hmac_sha256`, and parse-server calls `lp_frame_verify` on every accepted frame.
- It is also true that this implementation carries no masking; the `hmac` datasheet claims constant-time behaviour (no secret-dependent branches or memory accesses), not power-analysis resistance.

BUT the claimed attack is a **power-analysis (CPA) physical side channel**, which libparse `SECURITY.md` explicitly lists as **outside the threat model**:

> The following are outside our threat model: ... physical observation side channels (power consumption, electromagnetic emissions).

So the "CRITICAL key recovery" framing is a category the project has deliberately excluded. This is not a timing finding (which would be in scope for `verify`/`hmac`, since they claim and are checked for constant-time behaviour) — it is instantaneous power consumption on an embedded target, squarely the excluded class.

Correct triage: acknowledge the observation is technically valid, but explain it falls outside the documented threat model (physical observation side channels); libparse does not claim power-analysis resistance. Not a security issue per policy; **definitely not critical**. Optionally note mitigations *may* still be applied at maintainers' discretion per SECURITY.md, but there is no obligation and no severity assignment. Do not request a CVE. Do not label `sev:*`.

Verification: read `../libparse/SECURITY.md` "Threat model" section (the out-of-scope list) and `docs/modules/hmac.md` (constant-time claim line); confirmed `lp_hmac_sha256` context in `hmac.c`.
