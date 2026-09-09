# Severity calibration — published advisories

Anchor every new score against these. All CVSS vectors are CVSS v3.1 exactly as
published by the VMT. This is a 2026-07-10 snapshot of the **published**
advisories only — re-check the authoritative public lists, since new advisories
publish over time:
- https://github.com/example-org/libparse/security/advisories
- https://github.com/example-org/parse-server/security/advisories

**Confidentiality:** only published advisories are listed here. Never add
`triage`/`draft`/embargoed advisory content to this file or to any search.

> Example content: these six advisories are fictional (see
> `docs/security-reference/past-advisories.md`). Replace them with your own
> published advisories when you adopt this tracker.

## The anchor set

| CVE / GHSA | Repo | Severity | CVSS v3.1 vector | One-line reason |
|---|---|---|---|---|
| CVE-2024-90001 (GHSA-exmp-0001-frme) | libparse | **High 8.2** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` | 32-bit overflow sizing the record table in `lp_read_header`; heap overflow reachable from any `lp_frame_decode` caller before authentication. |
| CVE-2024-90002 (GHSA-exmp-0002-mac0) | libparse | **Medium 5.9** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` | Clang `-Os` turned `lp_mac_equal` into an early-exit compare; local PoC recovers the full MAC (forgery capability) in ~40 min. |
| CVE-2025-90003 (GHSA-exmp-0003-trlr) | libparse | **High 7.5** | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | `lp_frame_verify` compared only the truncated trailer length; one matching byte passed verification. No PoC needed — conclusive on reading. |
| CVE-2025-90004 (GHSA-exmp-0004-oobr) | libparse | **Medium 5.3** | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` | `lp_read_record` OOB read on a short final record; over-read bytes feed only the HMAC input. |
| CVE-2025-90005 (GHSA-exmp-0005-desn) | libparse | **Low 3.7** | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 32-bit nonce counter in legacy v0 collides after ~2^16 frames; no concrete attack. Unpatched by design (module deprecated, off by default). |
| CVE-2025-90006 (GHSA-exmp-0006-conn) | parse-server | **High 8.2** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H` | `conn_buf_reserve` added size to offset without overflow check; network-reachable crash + possible leak of adjacent connection state. |

## Reading the anchors

**High (7.5–8.2)** = either (a) a remotely triggerable memory-safety bug in a
network-facing parser with crash/leak potential (`AC:L`, `A:H`), or (b) an
authentication/integrity bypass that lets an attacker pass off content the key
holder never produced (`I:H`) — even with no demonstrated exploit (`AC:L`, no
C/A impact).

**Medium (5.3–5.9)** = two recurring shapes:
- Compiler-induced timing side channel with a working local PoC that recovers
  the **whole** secret — still only Medium because the attack is a
  high-complexity side channel (`AC:H`) with confidentiality-only impact. The
  timing advisory is exactly `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9.
- Out-of-bounds **reads** whose bytes cannot be exfiltrated and cannot make
  verification pass → impact collapses to a potential crash (`A:L`) = 5.3.

**Low (3.7)** = theoretical design weakness with no known concrete attack
(`C:L`, `AC:H`).

**Critical (9.0+)** has **no published precedent** as of this snapshot. Do not
reach for `sev:critical` by analogy to generic memory-safety CVEs; a finding
that would be Critical needs a low-complexity, network-reachable path to secret
recovery or forgery *combined with* a further impact (e.g. code execution or
scope change). If you think you have one, escalate to a human VMT member with
the vector and the reasoning.

## Load-bearing lessons

1. **Full secret recovery ≠ High/Critical.** The gate is attack complexity and
   whether the vector is a side channel. Timing secret-recovery PoCs are Medium
   5.9.
2. **"Where does the data flow / is there an oracle?"** For any read/overflow,
   trace the OOB bytes. If they feed only the HMAC input, are never returned,
   and can't flip a verify result, impact is `A:L`, not `C:H`. CVE-2025-90004
   argues exactly this.
3. **`AV:N` even for local timing demos.** Verify timing is remotely measurable
   in principle; the VMT publishes `AV:N` for these. Match the convention.
4. **No-PoC integrity bugs can still be High.** CVE-2025-90003 got 7.5 with no
   demonstrated exploit because the code path is conclusive and it undermines
   authentication at the core.
5. **Check for sibling vectors.** CVE-2025-90004 was found reviewing a 2.3.0
   change that fixed the *header* bound but not the *record* bound. A "fixed"
   bug may have relatives; a partial fix can warrant its own advisory.
6. **Length handling and compiler-vs-constant-time are repeat classes** —
   precedent is dense there; use it.

## Threat-model reminder

Timing side channels in `lp_mac_equal` and key loading are **in scope**
(tested on Linux x86_64; see the module datasheets and `libparse/SECURITY.md`).
Same-host side channels, hardware flaws, fault injection, and power/EM analysis
are **out of scope** — but may still receive best-effort mitigation. Scope
decisions belong to the threat-model-and-scope skill; this file is only for
scoring issues already judged in scope. Supported-version facts change every
release — read `SECURITY.md`, never hardcode them.
