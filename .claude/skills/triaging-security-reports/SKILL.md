---
name: triaging-security-reports
description: >-
  Use when triaging a new or untriaged tracker issue, a mirrored GHSA, or any
  incoming security report (issue text, forwarded email, advisory) for
  libparse or parse-server — the first pass, before any label, severity
  verdict, or reply is decided.
---

# Triaging security reports

The entry point for vulnerability triage. **Triage by CHECKING the report,
not by reading it**, and never anchor on the reporter's claimed severity — the
snapshot marks it "UNVERIFIED — assess independently."

**Confidentiality:** this repo is PRIVATE and embargo-sensitive. Never paste
report contents, advisory text, PoC code, or reporter identities into web
searches or any external service. Public-info lookups only (a published CVE, a
public paper).

## The discipline: verify before verdict

Work the gates **in order**. A hard fail short-circuits the rest.

0. **Snapshot & untrust.** Read the issue. Note the repo (`repo:*` label /
   `sources.yml`), GHSA state, and the reporter's claimed severity — record it
   as UNVERIFIED; do not let it set your expectations.
1. **Claim inventory.** List every checkable claim: named files, functions,
   macros, structs, line numbers, call flows, versions, build flags, PoC steps.
2. **Verify every symbol (slop gate).** Grep each named artifact in the correct
   clone at the right tag. **REQUIRED SUB-SKILL: detecting-report-slop.** No
   symbol check → no verdict. If the named project is not libparse /
   parse-server / a supported binding (no clone to grep), skip to the scope
   gate — do not hunt for its source. If load-bearing *existence* claims fail
   (named files/functions do not exist) → **fabricated; stop.** If the symbols
   are real, continue — you have proven only that the reporter read real code,
   NOT that the bug exists.
3. **Scope gate — BEFORE severity or reproduction.** **REQUIRED SUB-SKILL:
   threat-model-and-scope.** In order: (a) Is the named project in the
   security-support set (libparse, parse-server, the language bindings)? (b) Is
   the version supported (check the repo's `SECURITY.md`)? (c) Is the issue
   inside the threat model? A "no" at (a) = out-of-scope/unsupported **no matter
   how real the bug is**. Real bug + unsupported project = still out of scope.
4. **Impact reality-check.** **REQUIRED SUB-SKILL: assessing-severity.** What
   can an attacker actually reach and gain? Does the claimed impact follow from
   the claimed flaw? Recompute severity from scratch; never start from the
   reporter's vector.
5. **Verdict — VMT taxonomy.** Pick exactly one assessment outcome (see
   `reference.md` for the taxonomy and its tracker-disposition mapping).
   Confirmation requires evidence, not merely a plausible reading. For
   behavioral bugs (memory-safety, timing) that means reproduction; for an
   authentication/validation logic flaw it may mean conclusive analysis
   (PROCESS.md: 'reproduce or otherwise confirm'). Code-reading that only fails
   to disprove a mechanism never justifies `status:confirmed`.
6. **Output contract.** Deliver the triage report below. You **recommend**;
   a human applies labels, posts, and closes unless the operator explicitly
   delegated the action. Never edit the machine-owned snapshot region (above the
   `<!-- /ghsa-sync -->` marker).

## Calibration: the goal is NOT to reject

A missed real vulnerability costs far more than a wasted hour of reproduction.

- **Failure to DISPROVE is not grounds to dismiss.** If a report is coherent and
  names real code, inability to confirm the *mechanism* by reading is expected —
  data-dependent bugs cannot be disproven by code-reading. Verdict = **credible
  — needs reproduction** (REQUIRED SUB-SKILL: reproducing-security-reports), not
  fabricated. Fabricated is only for failed *existence* checks.
- **Uncertainty escalates to a human VMT member.** Never silently convert "I
  couldn't confirm" into "invalid," and never quietly downgrade to close it.

## Verdict → recommended labels (quick map)

Only labels defined in `scripts/setup-labels.sh` are legal — never invent one
(no `repo:parse-playground`, `needs-repro`, `type:vulnerability`,
`type:*(provisional)`). The only legal `type:*` values are
`type:memory-safety`, `type:side-channel`, `type:logic-flaw`,
`type:supply-chain`, `type:upstream` — pick by the flaw's nature (a
memory-safety bug is `type:memory-safety`, not `type:vulnerability`).
See also **operating-the-tracker** for the full taxonomy and `gh` recipes.

| Verdict | Recommend | Open/close |
|---|---|---|
| Fabricated / invalid | `status:wontfix` | close (not planned) |
| Duplicate | `status:duplicate` | close (not planned) |
| Out of scope: unsupported project | polite redirect; no `repo:*` exists for it — do not invent one; `status:wontfix` only if a tracker issue must be closed | close (not planned) |
| Out of scope: outside threat model (real observation) | `not-a-security-issue` (+ `type:*` if a real code bug) | close (not planned) |
| Working-as-intended / Bug / Feature request | `not-a-security-issue` | close (not planned) |
| Vulnerability, **not yet confirmed** | keep `status:triage` (+ `type:*`); recommend reproduction / conclusive analysis | stays open |
| Vulnerability, **confirmed** (reproduced, or conclusive analysis for a logic flaw) | `status:confirmed` + one `sev:*` + `type:*` (+ `embargoed` if applicable) | open |

Invariants: exactly one `sev:*`; `status` is a single axis; `status:confirmed`
means a **confirmed security issue** (reproduced, or conclusively analyzed for
a logic flaw) and **never** combines with `not-a-security-issue`.

## Output contract — triage report template

```
## Triage report — <issue # / title>

**Verdict:** <one VMT assessment outcome>
**Confidence:** <high | medium | low — and why>

**Claims checked (evidence):**
| Claim | Check performed | Result |
|---|---|---|
| lp_read_record() in src/frame/decode.c | grep in libparse @ <tag> | exists — decode.c:118 |
| <symbol/path/flow> | <grep / trace / signature check> | <exists / not found / differs> |

**Scope analysis:** project in support set? <y/n + which>; version supported?
<per SECURITY.md>; inside threat model? <y/n + which clause>.

**Impact / severity:** <attacker context + reachable gain; recomputed CVSS if
applicable — see assessing-severity>. Reporter's claimed severity (<x>) is
UNVERIFIED and not used.

**Recommended labels:** <only labels from setup-labels.sh>

**Recommended next step:** <reproduce / request runnable PoC / close as … /
escalate to a VMT member>

**Draft reply to reporter:** <courteous draft — see responding-to-reporters>

_Recommendation only — a human applies labels, posts, and closes unless
explicitly delegated._
```

When you **post** this report to GitHub yourself (a delegated comment), it MUST
end with the agent-attribution footer — see **operating-the-tracker** → "Mark
agent-written content."

After a confirmed vulnerability, hand off to **coordinating-fix-and-disclosure**.

## Rationalizations to reject

| Rationalization | Reality |
|---|---|
| "Detailed and professional, so it's probably real." | Detail is cheap for LLMs; the polished reports are often the fabricated ones. Grep the symbols. |
| "The overflow mechanism doesn't match the code I read, so it's fabricated." | Reading code cannot disprove a data-dependent bug. If the symbols exist → credible — needs reproduction, NOT fabricated. |
| "I couldn't reproduce it quickly, so reject." | Non-repro ≠ invalid. Document exactly what you tried and hand to a human. |
| "Reporter says CVSS 9.8." | Recompute from scratch. Reporter severity is never trusted. |
| "It mentions timing, and timing is in scope, so it's valid." | Check the specific module's constant-time claim in its datasheet first (power/EM analysis is out of the threat model). |
| "I found a real bug in the playground — open a libparse advisory + CVE." | Scope gate runs first. Unsupported project = out of scope regardless of how real the bug is. |
| "It's out of the threat model, mark it status:confirmed + working-as-intended." | `status:confirmed` is for confirmed *security* issues only. Use `not-a-security-issue`. |

## Red flags — STOP if you are about to

- Write a verdict without having grepped **every** named symbol.
- Do reproduction or severity before checking the project/version is in scope.
- Recommend a label that is not in `setup-labels.sh`.
- Recommend `status:confirmed` on a plausible read alone (no reproduction and no
  conclusive analysis).
- Paste report text, PoC, or a reporter's name into a web search.

## Fixtures

`fixtures/` holds regression fixtures with known ground truth for exercising
this process — **not real reports**. See `fixtures/README.md`.
