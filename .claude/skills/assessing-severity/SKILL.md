---
name: assessing-severity
description: >
  Use when assigning a sev:* label or CVSS score to a confirmed or credible
  libparse or parse-server security issue, or when sanity-checking a
  reporter's claimed severity or CVSS.
---

# Assessing severity

Independent CVSS + `sev:*` for a libparse / parse-server issue. Output is a
**recommendation** for a human to apply (PROCESS.md step 3 is human-owned).
Legal labels, exactly one: `sev:critical` `sev:high` `sev:medium` `sev:low`.

**Confidentiality:** this repo is private and embargo-sensitive. Never paste
report contents, advisory drafts, or reporter identities into a web search or
any external service. Look up only already-public info (a published CVE/paper).

## Rule zero: the score is ours

Recompute from scratch. Never start from the reporter's vector or CVSS — reported
severity is never trusted (README). A reporter's "CVSS 9.8" is marketing; a real
full-secret-recovery timing PoC is Medium 5.9 in this project's practice (see
anchors).

## Step 1 — Which attacker reaches this? (three exposure contexts)

1. **Direct libparse API caller** — the application calls `lp_frame_decode` /
   `lp_frame_verify` on bytes it obtained somewhere. Attacker influence =
   whatever untrusted bytes the app feeds in (a frame, a key blob). Malformed
   *local-only* input is weakest.
2. **Network attacker via parse-server** — attacker-supplied frames hit
   `lp_frame_decode` **before any authentication**, then `lp_frame_verify`
   under the per-client key (see `docs/security-reference/parse-server.md`).
   This is the realistic worst-case deployment; usually gives `AV:N/PR:N`.
3. **Local / physical** — same-host side channel, power/EM, fault injection.
   Mostly **out of threat model** (see also: threat-model-and-scope). An
   out-of-model finding is not automatically Low, but rarely High.

Score the library's realistic worst deployment (GitHub advisory norm) — normally
context 2, the parse-server-facing-the-network path.

## Step 2 — Impact ladder (highest first)

Key / MAC-secret recovery > forgery or accepting an unauthenticated frame >
security-relevant correctness failure (e.g. a verified frame decodes to content
the signer did not produce) > crash/DoS on attacker-supplied **network** input >
crash on malformed **local** input > leak needing out-of-model access.

**Oracle analysis is load-bearing.** For a memory bug, trace where the data
goes: an out-of-bounds *read* whose bytes feed only the HMAC input — never
returned, can't make `lp_frame_verify` accept a frame — collapses to `A:L`
(crash), not `C:H`. Do this before scoring any read/overflow.

## Step 3 — Modifiers

- **Attack complexity:** millions of precise timing samples or a side channel →
  `AC:H`. One crafted frame / one connection → `AC:L`.
- **Reach:** default-on module (`decode`, `verify`, `hmac`, `key`) → wider blast
  radius; default-off module (`legacy_v0`, `LP_ENABLE_LEGACY_V0`) → narrower,
  only users who enabled it.
- **Claimed vs unclaimed property:** breaking a property the module datasheet
  promises (e.g. constant-time where `docs/modules/verify.md` says "claim:
  yes") is more serious than one it never claimed. Check the datasheet first.
- Project convention: publish **`AV:N` even for locally-demonstrated timing
  attacks** (verify timing is remotely measurable in principle). Match it.

## Step 4 — CVSS 3.1 and the sev band

Record a full **CVSS:3.1** vector **and** a prose justification. CVSS fits
authentication-quality issues imperfectly, so the `sev:*` label is our judgment
*informed by* the CVSS band, not slaved to it. Rough map: 9.0+ critical,
7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low — but let the anchors below override
naive intuition.

## Calibration anchors (published advisories)

Anchor every score against precedent. Full table with vectors and reasoning in
**calibration.md** (same directory). Headlines:

| Situation | Precedent | Result |
|---|---|---|
| Full MAC-secret recovery via **timing side channel**, working local PoC | CVE-2024-90002 | **Medium 5.9** (`AC:H`, C:H only) — NOT critical |
| Authentication bypass: verify accepts a frame the key holder never produced, no PoC needed | CVE-2025-90003 | **High 7.5** (`AV:N/AC:L`, `I:H` only) |
| Remotely-triggerable memory bug in a network-facing parser (crash/leak) | CVE-2024-90001; parse-server CVE-2025-90006 | **High 8.2** (`AV:N/AC:L`, `A:H`, `C:L`) |
| OOB **read**, bytes feed only the HMAC input, no oracle | CVE-2025-90004 | **Medium 5.3** (`A:L` only) |
| Theoretical design weakness, no concrete attack | CVE-2025-90005 | **Low 3.7** (`C:L`, `AC:H`) |

**Full secret recovery does NOT imply High/Critical.** If it needs a side
channel, `AC:H` + C-only impact caps it at Medium. This is the #1 inflation
trap.

## Output contract

Deliver: (1) `sev:*` recommendation; (2) full CVSS:3.1 vector; (3) a
justification paragraph naming the exposure context, the point on the impact
ladder, and the closest anchor; (4) **what evidence would change the score** —
e.g. "a demonstrated leak oracle for the OOB bytes would raise C:N→C:L and push
this toward High." Recommend; a human applies the label.

## Red flags — stop and recheck

The calibration anchors already cover "full secret recovery ≠ Critical" and
"trace the data/oracle"; these are the remaining traps.

| Rationalization | Reality |
|---|---|
| "Reporter says CVSS 9.8" | Recompute from scratch. Reporter scores are marketing. |
| "It's local, so Low" | Local timing → still `AV:N` by project convention; score the impact, not the demo setup. |
| "CVSS band says X, done" | `sev:*` is our judgment; anchor to precedent, write the justification. |
| "It's a parser crash, parsers are always High" | Only if network-reachable with `AC:L`; a crash on a default-off module or local-only input scores lower. |

If the impact analysis is genuinely uncertain, say so and escalate to a human
VMT member — do not guess a band.

See also: threat-model-and-scope (is it even in scope), triaging-security-reports (entry point).
