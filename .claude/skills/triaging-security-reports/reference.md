# VMT assessment taxonomy — reference

Source of truth: `governance/security/response-process.md` (Phase 2,
Assessment) and `security-tracking/PROCESS.md`. Every triage verdict is exactly
**one** outcome below. Labels below are illustrative of the mapping — the
authoritative legal list is `scripts/setup-labels.sh` (see
**operating-the-tracker**); never invent a label.

## Primary assessment outcomes

| Assessment | VMT response (per process doc) | Tracker disposition |
|---|---|---|
| **Working as intended** | Tell reporter it's intended behavior; they may file a feature request. Response lead explains the reasoning. Close the security issue. | `not-a-security-issue`; close (not planned) |
| **Bug** | Tell reporter it's unwanted but not a security issue; ask them to refile as a public bug. Close the security issue. | `not-a-security-issue` (may still be fixed as a normal bug via a linked PR); close (not planned) |
| **Feature request** | Tell reporter it's intended behavior; they may file a feature request. Close the security issue. | `not-a-security-issue`; close (not planned) |
| **Vulnerability** | Tell reporter the VMT confirmed a security issue; proceed with the process. | confirmed (reproduced, or conclusive analysis for a logic flaw) → `status:confirmed` + one `sev:*` + `type:*` (+ `embargoed`); stays open. Not yet confirmed → keep `status:triage`, seek reproduction. |
| **Out of scope** | Tell reporter it's out of scope; if applicable, help refile upstream. See sub-table. | depends on sub-type below |

Not in the process doc but a real triage outcome: **Fabricated / invalid**
(load-bearing existence claims failed the slop gate) and **Duplicate** →
`status:wontfix` / `status:duplicate`, close (not planned).

## "Out of scope" sub-table

libparse vendors some upstream code (the SHA-256 implementation under
`src/mac/`, pinned in `third_party/UPSTREAM.md`) and assumes no obligation to
fix upstream vulnerabilities, but may do so on a best-effort basis. For
out-of-scope assessments involving upstream code, pass the report to the
relevant upstream(s); if libparse patches locally but upstream stays unfixed,
the published advisory must warn of this.

| Sub-type | Description | Additional action | Tracker disposition |
|---|---|---|---|
| **Outside threat model** | Issue lies outside the libparse threat model (e.g. power/EM analysis, fault injection, same-physical-system side channels, documented API misuse). | Decide whether severity warrants a patch irrespective of scope. | `not-a-security-issue`; point reporter at `SECURITY.md` threat model; may still be fixed best-effort. Close (not planned). **Not `sev:*`, not `status:confirmed`.** |
| **Unsupported project** | Issue is in an example-org repo without security support (e.g. parse-playground, parse-cli). | Decide whether to patch anyway; if not, document in that repo. | Polite best-effort redirect; do NOT run CVE/advisory machinery on the unsupported repo alone. No `repo:*` label exists for out-of-scope projects — do not invent one. |
| **Unable to assess** | Assessment needs upstream domain knowledge beyond the VMT's. | Monitor the upstream for resolution. | Escalate to a VMT member; leave open, note status in prose. |
| **Vulnerability: can patch** | A real vulnerability, simply patchable within libparse. | Decide whether to develop a patch; coordinate disclosure with upstream. | Treat as **Vulnerability** above once reproduced. |
| **Vulnerability: can't patch** | A real vulnerability, not simply patchable within libparse. | Coordinate disclosure with upstream; monitor; consider dropping the dependency depending on severity. | Treat as **Vulnerability**; escalate the drop/monitor decision to the VMT. |

## Scope nuance (the trap in the "unsupported project" case)

If the described flaw traces to a genuine defect **in libparse itself** (a
supported project), that libparse-level portion IS in scope even if the report
arrived framed around an unsupported repo. But a bug in the unsupported repo's
own glue code (not in a libparse/parse-server API) is out of scope as reported.
Read where the defect actually lives before deciding.

## Confirmation requires evidence

Confirmation requires evidence, not merely a plausible reading. For behavioral
bugs (memory-safety, timing) that means reproduction; for an authentication or
validation logic flaw it may mean conclusive analysis (PROCESS.md: 'reproduce
or otherwise confirm'). Code-reading that only fails to disprove a mechanism
never justifies `status:confirmed` — it yields **credible — needs
reproduction** (keep `status:triage`), not `status:confirmed` and not
fabricated. See the calibration section of SKILL.md and
**reproducing-security-reports**.
