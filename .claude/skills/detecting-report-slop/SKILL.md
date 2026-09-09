---
name: detecting-report-slop
description: >-
  Use when judging whether a security report (issue, email, GHSA) is
  fabricated or LLM-generated, when a report feels generic or too polished,
  or before investing reproduction effort in one.
---

# Detecting report slop

Fabricated and LLM-generated reports are the polished ones — detail is cheap.
You cannot judge a report by reading it. You judge it by **checking** it: every
named artifact gets grepped in the real code. This skill is the verification
protocol; it hands its result back to `triaging-security-reports`.

**Confidentiality:** this repo is private and embargo-sensitive. Never paste
report text, advisory content, or reporter identities into a web search or any
external service. Only look up already-public facts (a published CVE, a paper).

## The one rule that inverts everything

- **Absent load-bearing symbol → fabricated.** If a function/file/macro the
  claim *depends on* does not exist, the reporter never read the code. Verdict:
  fabricated.
- **Real symbols + unproven mechanism → NOT fabricated.** Reading code cannot
  disprove a data-dependent bug. If the named artifacts all exist but you can't
  confirm the *mechanism* by reading, the verdict is **needs-more-info /
  credible**, and you escalate to reproduction — never "fabricated." Failing to
  disprove a claim is not evidence it is false. (This is the #1 real failure:
  dismissing a genuine bug because the mechanism "didn't match the code I read.")

## Symbol-verification protocol (the heart)

1. **Pick the right repo + version.** libparse API report → the libparse clone
   (`../libparse`). parse-server / network report → the parse-server clone
   (`../parse-server`). Check the version/tag the report targets. Public API
   lives in `include/libparse/frame.h`, `include/libparse/key.h`,
   `include/libparse/errors.h`.
2. **Extract every named artifact:** functions, files, macros, structs,
   constants, line numbers, API call sequences, CVE/CWE references.
3. **Grep each one** in that repo: `grep -rn "lp_frame_decode" src/ include/`.
   Record exists / absent / exists-but-different (wrong signature, wrong file,
   wrong line). One absent load-bearing symbol ends the investigation — see the
   rule above. Non-load-bearing typos (a mislabeled line number, a real function
   in the "wrong" file) are noise, not fabrication.
4. **Coherence checks** on what does exist:
   - Does the claimed call flow exist? Trace it in the source.
   - Does the PoC type-check against real signatures? Compare argument order and
     types to `frame.h`/`key.h` (e.g. `lp_frame_decode(buf, len, &frame)`).
   - Does a supplied patch diff apply to the real file?
   - Right repo? A "libparse" report citing parse-server socket APIs (or vice
     versa) is confused. Note: parse-server verifies **after** decoding, so a
     `lp_frame_decode` bug is pre-authentication, while a `lp_frame_verify` bug
     needs a frame that reaches the key step. A report against the legacy v0
     decoder (`LP_ENABLE_LEGACY_V0`) only affects users who enabled it — it is
     off by default.
   - Terminology sanity: `lp_frame_decode` never touches a key (it parses
     structure only); the MAC trailer is a fixed 32 bytes, not a "variable-length
     signature"; frame header fields are magic, version, varint record count —
     a report describing an "extension length" field misreads the format
     (`docs/format.md`). Check the module datasheet before trusting a
     constant-time claim.

## Slop signals (secondary — never sufficient alone)

| Signal | Why it only justifies deeper checking |
|---|---|
| CVSS 9.8 with no runnable PoC | Score is marketing; recompute independently |
| CWE walls / boilerplate ("As an AI researcher…") | Padding, not evidence |
| Generic mitigation advice, no specifics | LLM filler |
| Terminology mismatch (signature ↔ MAC trailer; "extension field") | Author didn't read the format doc |
| Identical text filed against many projects | Spray-and-pray (search only if public) |

Slop signals raise suspicion and justify closer verification. They **never**
justify a fabricated verdict on their own — only failed verification of a
load-bearing claim does.

## The runnable-PoC filter

When symbols are real but the mechanism is unproven (mixed verdict), recommend
asking the reporter for a **minimal runnable PoC**. This is a cheap, standard
filter: genuine reporters produce one; spammers vanish. (See also:
`responding-to-reporters` for the request template.)

libparse's `SECURITY.md` links a reporting template that asks for Threat Model
Fit, Affected Target, Reproduction, Expected Output, and a PoC/regression
test. A report that fills those sections with real, checkable content is a
positive signal (still verify the symbols); a report ignoring the template
while claiming critical impact warrants the PoC request before any effort is
spent.

## Output shape

Return a claim table plus a verdict — do not apply labels (that's the human's
job via `triaging-security-reports`).

| Claim | Check performed | Result |
|---|---|---|
| `lp_frame_unpack_ext` in decode_fast.c | grep src/frame/ | absent — no such symbol |
| `lp_read_record` OOB write | grep decode.c + trace decode path | exists; mechanism unconfirmed by reading |

**Verdict** (apply the rule above) — one of:
- **verified-credible** — artifacts exist and the flaw is coherent; needs reproduction.
- **mixed / needs-more-info** — real symbols, unproven mechanism; request a runnable PoC, escalate to reproduction.
- **fabricated** — name exactly which load-bearing symbol is absent: "the referenced function `X` does not exist in libparse `src/frame/…`."

When uncertain, escalate to a human VMT member. A missed real vulnerability
costs far more than an hour spent verifying a fake one.
