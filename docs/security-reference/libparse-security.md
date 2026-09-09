# libparse security ground truth (example fact pack)

Snapshot of `../libparse/SECURITY.md`, `README.md` and `PLATFORMS.md` as of
2026-07-10. Anything marked **VOLATILE** must be re-checked in the cited file,
never hardcoded. **All of this is fictional example content** — see
`README.md` in this directory.

---

## 1. What libparse is

`example-org/libparse` is a C library that decodes and authenticates
**length-prefixed binary frames** ("Parse Frame Format", PFF). A frame is a
fixed header, a variable number of records, and an HMAC-SHA-256 trailer over
everything before it. Consumers hand libparse untrusted bytes (from a socket, a
file, a message queue) and get back either a decoded frame that verified under
a key, or an error.

The public API is small (see `libparse-components.md`):
`lp_frame_decode`, `lp_frame_verify`, `lp_frame_free`, `lp_key_load`,
`lp_key_free`.

## 2. Supported versions policy

Source: `../libparse/SECURITY.md`, "Supported Versions".

Policy (stable): **"We support only the most recent minor release line."**

Current table — **VOLATILE: check SECURITY.md before quoting**:

> | Version | Supported |
> | ------- | --------- |
> | 2.4.x   | yes       |
> | < 2.4   | no        |

SECURITY.md also says: "Using any release before 2.2.0 is strongly discouraged
because of a known frame-parsing vulnerability (see the published advisory
GHSA-exmp-0001-frme)."

## 3. Threat model — VERBATIM from SECURITY.md

> ## Threat model
>
> libparse is designed to be handed attacker-controlled bytes. The following
> are **in scope**:
>
> - Memory-safety failures (out-of-bounds read or write, use-after-free,
>   uninitialised memory) triggered by any input to a public API function.
> - Authentication failures: any input that `lp_frame_verify` accepts under a
>   key that did not produce it, or any way to make a verified frame decode to
>   content the signer did not produce.
> - Timing side channels in the MAC comparison (`lp_mac_equal`) and in key
>   loading. We test these with a Valgrind-based harness on Linux x86_64 (see
>   `tests/ct/`). Where a module's documentation says it makes no constant-time
>   claim, a timing report against it is tracked as a limitation, not as a
>   vulnerability. Timing reports outside the tested scope are considered
>   case-by-case, with priority on Tier 1 platforms (see `PLATFORMS.md`).
> - Resource exhaustion that is disproportionate to input size (a small frame
>   that forces a large allocation or unbounded work).
>
> The following are **outside** our threat model:
>
> - same-physical-system side channels (cache attacks from a co-resident
>   process, shared-hardware attacks)
> - CPU / hardware flaws
> - physical fault injection (including Rowhammer-style attacks)
> - physical observation side channels (power consumption, electromagnetic
>   emissions)
> - misuse of the API contrary to the documentation (for example verifying a
>   frame with a key the caller already leaked)
>
> Mitigations for issues outside the stated threat model may still be applied
> depending on the nature of the issue and the cost of the mitigation.

Triage-relevant readings:
- "Designed to be handed attacker-controlled bytes" means malformed input to a
  public API is always a legitimate attacker context, even with no network.
- Constant-time claims are **per module** (see `libparse-components.md`); the
  absence of a claim is not a bug.
- Out of scope does not mean never fixed.

## 4. Constant-time test evidence locations

Verified to exist in the clone:

- `../libparse/tests/ct/` — the Valgrind harness (`ct_harness.c`,
  `run_ct.py`) plus `passes/` and `issues/` suppression directories with
  `passes.json` / `issues.json` indexes. "Passes" are findings audited as
  false positives; "issues" are known or suspected leaks.
- `../libparse/docs/modules/*.md` — per-module datasheets, each with a
  "Constant-time claim" line and a "Checked by Valgrind" line.

## 5. Support limitations (README.md)

> #### Support limitations
>
> libparse is maintained by volunteers on a best-effort basis. Guidelines,
> support tiers and response times reflect current practice and may change at
> any time.

## 6. Platform tiers (PLATFORMS.md) — VOLATILE list, read the file

- **Tier 1** — "guaranteed to work": CI builds and tests every change. Targets
  marked † are additionally run through the constant-time harness in CI.
  PLATFORMS.md warns this does not *guarantee* constant-time behaviour.
  Tier 1 platforms are prioritised for security support.
- **Tier 2** — "guaranteed to build": CI builds; tests may not run.
- **Tier 3** — supported in code but neither built nor tested in CI.

As of 2026-07-10:

- Tier 1: x86_64 Ubuntu 24.04 †, aarch64 Ubuntu 24.04, x86_64 macOS 14,
  aarch64 macOS 14
- Tier 2: Windows x64 (MSVC 2022), FreeBSD 14 x86_64
- Tier 3: armv7 Linux, riscv64 Linux

## 7. Vulnerability reporting channels

Source: `../governance/security/response-process.md`, Intake section.

- Two endorsed channels: (1) email to **security@example.org** (an alias for
  the VMT); (2) a **GitHub Security Advisory** filed on the affected repo
  (private; arrives in "Triage" state).
- The on-call VMT member acknowledges within 1–2 days: email → reply to the
  reporter cc'ing security@example.org; GHSA → comment on the advisory. The
  acknowledging member becomes the **response lead** for that report.
- Reports that arrive by other channels (chat, a public issue) are moved into
  an endorsed channel by whoever notices them.

## 8. Security response process linkage

- SECURITY.md defers to the organisation-wide process in
  `../governance/security/response-process.md`.
- PLATFORMS.md ties platform tier to security priority.
- Past post-mortems live in `../governance/security/reports/`
  (template `YYYYMMDD-template.md`).
