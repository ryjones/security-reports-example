---
name: threat-model-and-scope
description: >-
  Use when deciding whether a security report is in scope — whether the named
  project has security support, whether the version is supported, whether the
  issue is inside the libparse threat model, or whether a timing/side-channel
  claim violates a property the module actually claims. Also when asked "is X
  a security issue for libparse / parse-server?" or which projects/versions
  get security support.
---

# Threat model and scope

Reference for scope decisions. Full quotes, support-boundary detail, and the
datasheet-reading recipe live in `scope-reference.md` (read it by name when you
need the verbatim threat model or per-module constant-time status).

**Confidentiality:** this repo is private and embargo-sensitive. Never paste
report contents, advisory text, or reporter identities into web searches or any
external service. Public-info lookups only (a published CVE, a public paper).

**You RECOMMEND a disposition.** A human applies labels and closes issues unless
the operator explicitly delegated it.

## The scope gate runs FIRST — before reproduction or severity

A real bug in an unsupported project is still out of scope. Never run the full
advisory workup until the gate passes. Ask, in this order, and STOP at the first
"no":

1. **Supported project?** Security support covers **libparse** (full process)
   plus **parse-server** and the language bindings **libparse-python /
   libparse-go** (lock-step: same-CVE advisories and releases cut alongside
   the libparse fix). Anything else — `parse-playground`, `parse-cli`, other
   repos — has **no security support** (best-effort only). Authoritative:
   `governance/security/response-process.md` scope section; `sources.yml`
   lists the repos this tracker mirrors. → No: **out-of-scope / unsupported
   project.**
2. **Supported version?** libparse supports **only the most recent minor
   release line** — check the target repo's `SECURITY.md` "Supported
   Versions", never hardcode. Report against an older version → check whether
   it is **already fixed** in the latest release (git-log the file) before
   doing anything else.
3. **Inside the threat model?** Memory safety, authentication failures, and
   timing in the MAC comparison / key loading are in scope; physical /
   hardware / fault-injection / same-host attacks are not (table below). →
   No: **out-of-scope / outside threat model** (a best-effort fix may still
   be applied). Authoritative source is the target repo's `SECURITY.md`.
4. **Does the module datasheet claim the property allegedly violated?** For
   any timing claim, read `libparse/docs/modules/<module>.md` — the
   "Constant-time claim" and "Checked by Valgrind" lines — FIRST (recipe in
   `scope-reference.md`). A leak in a module that claims nothing violates
   nothing.

A "no" at step 1 or 2 decides the disposition regardless of how real the bug is.

## Threat model at a glance (verbatim quote in scope-reference.md)

| Attack class | In scope? |
|---|---|
| Memory-safety failure on any input to a public API function | **Yes** |
| Authentication failure (verify accepts what the key did not produce; verified frame decodes to unsigned content) | **Yes** |
| Timing in `lp_mac_equal` / key loading (Valgrind-tested on Linux x86_64) | **Yes** — a leak is a regression |
| Timing in a module that claims nothing (`decode`, `varint`, `legacy_v0`) | Documented limitation → **case-by-case** |
| Timing outside the tested scope / platform | **Case-by-case**, Tier-1 priority |
| Resource exhaustion disproportionate to input size | **Yes** |
| Same-physical-system side channel | **No** |
| CPU / hardware flaws | **No** |
| Physical fault injection (incl. Rowhammer-style) | **No** |
| Physical observation (power, EM) | **No** |
| API misuse contrary to the documentation | **No** |

Out-of-scope ≠ never fixed: "Mitigations for issues outside the stated threat
model may still be applied" (SECURITY.md).

## Modules, defaults and constant-time expectations

- **Constant-time claims are per module** — read each datasheet's
  "Constant-time claim" line; the set changes per release. `verify`
  (`lp_mac_equal`), `hmac` and `key` claim it and are Valgrind-checked on
  x86_64; `decode` and `varint` claim nothing (parsing is expected to be
  variable-time); `legacy_v0` claims nothing and "no constant-time analysis
  has been done."
- **A "no claim" also covers "never analysed,"** not just "known to leak."
- **`legacy_v0` is OFF by default** (`LP_ENABLE_LEGACY_V0`); a report against
  it only affects users who enabled it. Confirm current defaults in
  `libparse/cmake/options.cmake`.
- Never assume from memory which module claims/passes. Authoritative: the
  datasheets under `libparse/docs/modules/<module>.md`;
  `docs/security-reference/libparse-components.md` is a dated in-repo
  snapshot. Recipe and cheat-sheet: `scope-reference.md`.
- Also check `libparse/docs/modules/README.md`: it lists **known /
  already-rejected timing patterns** (record-count-dependent loop timing in
  `lp_frame_decode`; early exit on bad magic in `lp_read_header`). A timing
  report matching a documented pattern there is a known limitation, not a new
  finding.

## Report pattern → likely disposition

| Report pattern | Likely disposition |
|---|---|
| Power / EM / fault-injection / Rowhammer / same-host side channel | Outside threat model (best-effort fix possible) |
| Timing outside the tested scope or on a non-Tier-1 platform | Case-by-case, Tier-1 priority |
| Timing leak in a module whose datasheet does **not** claim constant-time (`decode`, `varint`, `legacy_v0`) | Not a violated claim → documented limitation, case-by-case |
| Timing leak in a module that claims **and** is checked (`verify`, `hmac`, `key` on x86_64) | Inside threat model — treat seriously |
| Crash / OOB / memory-safety on attacker-supplied input to `lp_frame_decode` / `lp_frame_verify` / `lp_key_load` | In scope |
| `lp_frame_verify` accepts a frame the key did not produce | In scope — highest priority |
| Bug in `parse-playground`, `parse-cli`, or another unsupported repo | Out-of-scope / unsupported project |
| Report against a pre-latest version | Check whether already fixed in latest release |
| "Parsing untrusted input is inherently unsafe" / design philosophy | Working as intended |
| Flaw in the vendored SHA-256 (`src/mac/sha256.c`) | Out-of-scope upstream; pass to upstream; libparse may patch best-effort |

## Out-of-scope assessment sub-types (governance/security/response-process.md)

When the verdict is out-of-scope, name the sub-type — each has a different
follow-up (full table in `scope-reference.md`):

| Sub-type | Meaning |
|---|---|
| Outside threat model | Real but outside the model; decide on a best-effort patch |
| Unsupported project | In a repo without security support |
| Unable to assess | Needs upstream domain knowledge beyond the VMT |
| Vulnerability: can patch | Real vuln, easily fixed locally |
| Vulnerability: can't patch | Real vuln, not simply patchable locally |

## Do NOT

- Skip the scope gate and jump to reproduction/severity because the bug "looks
  real." That is the #1 baseline failure. Scope first, always.
- Downgrade an out-of-model report to "not a bug" — it may still be a genuine
  code-quality bug and may still get a best-effort fix. See sibling skill
  `operating-the-tracker` for `not-a-security-issue` vs `status:wontfix`.
- Treat a timing report as valid just because "timing is in the threat model" —
  check the specific module's constant-time claim first (step 4).

See also: `triaging-security-reports` (entry point), `assessing-severity`,
`reproducing-security-reports`.
