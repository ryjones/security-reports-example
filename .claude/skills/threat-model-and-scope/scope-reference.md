# Scope reference — verbatim quotes, support boundary, datasheet recipe

Companion to `SKILL.md`. Everything version- or module-specific here can go
stale — the cited file in the local clone is always authoritative. Verify, don't
trust this document's snapshots.

> Example content: libparse, parse-server and their governance repo are
> fictional (see `docs/security-reference/README.md`). Replace the quotes and
> tables below with your own projects' when you adopt this tracker.

## 1. libparse threat model — VERBATIM

From `libparse/SECURITY.md`, "Threat model" section. Re-read the file if you
need to quote it to a reporter.

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

Key readings:
- "Designed to be handed attacker-controlled bytes": malformed input to a
  public API is always a legitimate attacker context, even with no network.
- Constant-time claims are **per module**; "no claim" is not a bug, and it also
  covers "never analysed." Absence of a Valgrind result is not a clean bill of
  health.
- The harness only covers `verify`, `hmac` and `key` on Linux x86_64; other
  platforms and modules are case-by-case.

## 2. Security-support boundary

Source: `governance/security/response-process.md` scope section;
`libparse/README.md` "Support limitations"; `sources.yml`.

- The formal response process applies in full to **libparse**. libparse is
  also "maintained by volunteers on a best-effort basis… may change at any
  time" (README support disclaimer) — there are no reliability guarantees.
- **parse-server** and the bindings **libparse-python, libparse-go** are in
  the security-support set via **lock-step**: their `main` tracks libparse
  `main` and they build against libparse versions marked supported, so a
  same-CVE advisory and a "consequent" release can be cut alongside each
  libparse security release with no extra dev effort. libparse-go MUST always
  get a new tagged release (it pins a libparse version); the others' releases
  are at VMT discretion.
- **No security support** (best-effort updates only): `parse-playground` (a
  browser demo uploading frames to a hosted parse-server), `parse-cli`
  (example tooling), and any other repo. A real bug here is still
  out-of-scope.
- Scope may expand; `sources.yml` is the live list of repos this tracker
  mirrors (currently libparse + parse-server). Read it rather than assuming.

## 3. Supported versions

- Policy (stable): "We support only the most recent minor release line" —
  `libparse/SECURITY.md`.
- The exact supported version number is **VOLATILE**: read the "Supported
  Versions" table in the target repo's `SECURITY.md`. Do not hardcode it.
- SECURITY.md also flags that releases before a stated version are strongly
  discouraged due to a known past vulnerability — again, read the current file.
- A report against an older version: check whether the issue is **already
  fixed** in the latest release before doing further work (`git log` the
  affected file / compare to the current tag). Already-fixed → tell the
  reporter to update.

## 4. Out-of-scope assessment sub-table — SUMMARIZED (governance/security/response-process.md)

The organisation vendors some upstream code (currently only the SHA-256
implementation); it assumes no obligation to fix upstream defects but may do
so best-effort. For any out-of-scope assessment involving upstream code, pass
the report to the relevant upstream. If libparse patches locally but upstream
stays unfixed, the published advisory must warn of this.

| "Out of scope" assessment | Description | Additional action |
|---|---|---|
| Outside threat model | Issue lies outside the documented threat model. | Decide whether severity warrants a patch irrespective of scope. |
| Unsupported project | Issue is in a repo without security support. | Decide whether to patch anyway; if not, document the issue in the affected repo. |
| Unable to assess | Assessing requires upstream domain knowledge beyond the VMT's. | Monitor the upstream for resolution. |
| Vulnerability: can patch | A real vulnerability, simply and easily patchable locally. | Decide whether to develop a patch. Coordinate disclosure with the upstream. |
| Vulnerability: can't patch | A real vulnerability, not simply patchable locally. | Coordinate disclosure with upstream; monitor for resolution; depending on severity, consider dropping the dependency. |

For a severe vuln that upstream is unlikely to patch in reasonable time, the
VMT may **replace or drop the vendored code** and publish an advisory
immediately. Longer response times are tolerated for deprecated modules
(`legacy_v0`) than for the default-on path.

## 5. Upstream-code policy

- `src/mac/sha256.c` is vendored from an external implementation;
  `third_party/UPSTREAM.md` names the source and pinned commit. An upstream fix
  is **not** automatically an in-tree fix, and vice versa — confirm the actual
  in-tree state.
- Everything else in libparse is first-party. A report that blames "the
  SHA-256 library" should be checked against the pinned commit before being
  forwarded.

## 6. Platform tiers (libparse/PLATFORMS.md) — VOLATILE list, read the file

- **Tier 1** — "guaranteed to work": CI builds and tests every change; targets
  marked with a dagger (†) are additionally run through the constant-time
  harness in CI. PLATFORMS.md warns this does **not** guarantee constant-time
  behaviour. Tier 1 platforms are **prioritized for security support**.
- **Tier 2** — "guaranteed to build"; testing may or may not run.
- **Tier 3** — supported in code but neither built nor tested in CI.
- As of last read: Tier 1 = x86_64 Ubuntu 24.04 † (the only †
  constant-time-tested target), aarch64 Ubuntu 24.04, x86_64 macOS 14, aarch64
  macOS 14; Tier 2 = Windows x64 (MSVC 2022), FreeBSD 14 x86_64; Tier 3 = armv7
  Linux, riscv64 Linux — but the exact platform list is VOLATILE; read
  `PLATFORMS.md`.

## 7. How to read a module datasheet

Datasheets: `libparse/docs/modules/<module>.md` (one per source module).
Those files are authoritative; `docs/security-reference/libparse-components.md`
is a dated in-repo snapshot.

For a report, read these fields:

1. **Default build** — is the module compiled in by default? `legacy_v0` is
   OFF (`LP_ENABLE_LEGACY_V0`); a report against it only affects users who
   enabled it. Confirm in `libparse/cmake/options.cmake`.
2. **Constant-time claim** — does the module *claim* constant-time behaviour?
   If **none**, a timing leak violates **no claim** (track it, but it is not a
   broken promise). "None" also covers "no analysis was ever done."
3. **Checked by Valgrind** — did the harness in `tests/ct/` actually exercise
   it, and on which platform? Claim = yes but checked = no (the aarch64 builds
   of `verify` and `hmac`) means the claim exists but was never tested.
4. **Contract notes** — e.g. `lp_frame_decode` parses structure only and never
   touches a key; `lp_frame_verify` must be called before any record is
   trusted. A report that assumes a different contract is API misuse.
5. **Upstream** line — first-party or vendored (`src/mac/sha256.c` only).
6. **Known / rejected patterns** — `docs/modules/README.md` lists timing
   patterns already assessed and rejected (record-count-dependent loop timing
   in `lp_frame_decode`; early exit in `lp_read_header` on bad magic — both
   operate on public data).

Also check the parsing limits: `LP_MAX_RECORDS` (4096) and `LP_MAX_RECORD`
(1 MiB) are compile-time defaults; a report that assumes other values is
against a non-default build.

## 8. "Is a timing leak in X a violation of a claimed property?" cheat-sheet

VOLATILE — confirm against the datasheet (authoritative) or the dated snapshot
`docs/security-reference/libparse-components.md`.

- **Never a claim violation** (claim = none): `frame/decode`, `codec/varint`,
  `codec/legacy_v0` (also off by default).
- **Claim exists but never checked** (claim = yes, Valgrind = no): the aarch64
  builds of `frame/verify` and `mac/hmac`.
- **Claimed and checked — a leak here is a regression** (claim = yes, Valgrind
  = yes on x86_64): `frame/verify` (`lp_mac_equal`), `mac/hmac`
  (`lp_hmac_sha256`), `key/key` (`lp_key_load`).
- Constant-time evidence/suppressions live in `libparse/tests/ct/{passes,issues}/`
  with `passes.json` / `issues.json` indexes. "passes" = assessed false
  positives; "issues" = known/suspected leaks. Check them before treating a
  timing report as new.
