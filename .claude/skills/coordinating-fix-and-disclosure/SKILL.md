---
name: coordinating-fix-and-disclosure
description: >-
  Use when a report has been assessed as a Vulnerability and the project is
  proceeding past triage.
---

# Coordinating fix and disclosure

Runs the post-confirmation phases of the VMT process. **Authoritative source
for every procedural step: `governance/security/response-process.md` — read
it; this skill is a per-phase checklist and label map, not a substitute.**
Phases here map to Patching → CVE → Public disclosure → Feedback
(Assessment/triage is covered by REQUIRED SUB-SKILL: triaging-security-reports).

**Confidentiality:** this repo is private and embargo-sensitive. Never paste
advisory text, patch diffs, reporter identities, or embargoed details into web
searches or any external service. Public-info lookups only (published CVEs,
published papers). In linked *public* fix PRs, describe the change neutrally —
no vulnerability details while embargoed.

**Recommend, don't act.** Produce drafts, checklists, and label
recommendations for a VMT member to apply. Do not create advisories, request
CVEs, publish, or apply labels unless the operator explicitly delegated it. The
response lead (the on-call VMT member who acknowledged the report) owns the
response. Never hand-edit a mirror issue's machine-owned snapshot region.

## Prerequisite: handoff from Assessment

Before Patching starts, confirm the response lead has: appointed domain
expert(s); assembled a response team of **the patch developer(s) + at least
two maintainers with write permissions on the affected repo + at least one
GitHub admin aware and available**; and responded to the reporter with the
"Vulnerability confirmed" assessment (see responding-to-reporters), offering
them a role in the fix. Tracker at this point: `status:confirmed`, one `sev:*`,
`type:*`, `embargoed` if applicable.

## Phase 3 — Patching  → `status:fix-in-progress` → `status:fix-ready`

1. Draft the GHSA **in the source repo**. If the report arrived as a GHSA, flip
   its state Triage → Draft; if it came by email, create a fresh advisory. Add
   the response team as collaborators; add the reporter if they want in.
2. Create the **private fork** off the advisory; add the response team (and
   willing reporter). Open the fix PR from the fork.
3. **NO-CI TRAP — the load-bearing rule of this phase.** Private security forks
   have **no project CI**. The patch MUST be tested **locally** and pass all CI
   tests for libparse **Tier 1 platforms** (see libparse `PLATFORMS.md` — do
   not hardcode the tier list) plus any lower-tier platform the issue
   explicitly affects. Add a regression test proving the bug is gone if at all
   possible (a new pair under `tests/vectors/` is the usual form). See also:
   reproducing-security-reports for the local build/sanitizer/vector recipes.
4. Approval: **at least two response-team members with write permissions** on
   the affected repo, plus the reporter if applicable.
5. After approval, **squash commits into one manually** — "Squash and merge" is
   not available on security advisories. Do NOT merge yet.
6. Concurrently, the domain expert finalizes the advisory text including a CVSS
   evaluation (REQUIRED SUB-SKILL: assessing-severity — score independently).
7. If a lower-tier platform can't be fixed in time, the VMT may drop that
   platform's support to expedite a Tier-1 release, weighing severity vs.
   effort. Tracker: `status:fix-in-progress`, then `status:fix-ready` once the
   PR is approved/merged and pending release.

## Phase 4 — CVE assignment  → `cve-requested` → `cve-assigned`

Request the CVE from **within the draft advisory** (GitHub acts as the CNA).
**Timing trap:** only *after* the patch is approved **and** the advisory text
(including CVSS) is finalized — not earlier. Tracker: `cve-requested`, then
`cve-assigned` when GitHub issues it.

## Recording credit on an advisory

Two channels, and they do different jobs.

**The structured credits field** takes GitHub user accounts and **one role each** —
you cannot record someone as both Finder and Remediation developer. Use
**`reporter`** for whoever found the issue: every published libparse advisory
does (one adds a second person as `analyst`). `finder` has never been used.
Do **not** mix roles across co-reporters — marking one Finder and the rest
Reporter reads as "the others merely relayed someone else's discovery," which
misrepresents independent rediscovery.

**The `## Credits` prose section** carries everything the field cannot: who
reported first, organisation names (the field takes users, not orgs), and who
wrote the patch. The field records role but **not ordering**, so reporting
priority exists only here. When moving someone from `remediation_developer` to
`reporter`, add a sentence such as "The fix was developed by X" or that credit
vanishes entirely.

Confirm preferred names and credit preferences with every reporter before
publishing — a GitHub handle is not a name, and the advisory is permanent.

## Phase 5 — Public disclosure  → `status:published`

Order matters — publish **only after** the patch is merged and any security
release is out:

1. Merge the advisory (needs a **GitHub admin**; may require overriding branch
   protections).
2. Prepare and publish a security release if warranted (whether one is needed
   is at VMT discretion).
3. Add patch specifics — commit hash, version info — to the advisory text.
4. Publish the advisory.
5. Announce on **security-announce@example.org**.

**Lock-step subproject rule.** For every libparse advisory/release, advisories
using the **same CVE** should be published on parse-server and the language
bindings (libparse-python, libparse-go) — confirm the current set in
governance/security/response-process.md. Whether those get security
*releases* is VMT discretion, **with one exception: libparse-go MUST get a new
tagged release**, because its build pins a specific libparse version.

Tracker: apply `status:published` (the hourly sync flips the GHSA state and
comments when upstream publishes — don't hand-edit the snapshot). Keep the
issue **open** through backports and downstream follow-up.

## Phase 6 — Feedback

The response lead files a post-mortem in the governance repo at
`governance/security/reports/`, from the template
`governance/security/reports/YYYYMMDD-template.md`, named
`YYYYMMDD-<vulnerability-name>.md` (dated by report creation; worked example:
`governance/security/reports/20250314-truncated-mac-trailer.md`). It records
process friction, not technical vuln details (those live in the advisories).
**Optional if work never proceeded past Assessment.**

## Embargo hygiene (spans all phases)

- Keep `embargoed` on the issue; record the agreed disclosure date in the board
  Embargo/disclosure-date field.
- Only the response team and people with a need-to-know may see embargoed
  details.
- **Notify downstream consumers/packagers before publication**, per the agreed
  date.
- If the project patches vendored upstream code but the upstream stays
  unfixed, the published advisory must warn of this.

## Closing the tracker issue

Close only when all follow-up (backports, lock-step releases, feedback report)
is done — the sync never auto-closes. Use `status:published` closed as
*completed*; `status:fixed` (closed *completed*) covers the fixed-with-no-
advisory path. See also: operating-the-tracker for close reasons and the
open-vs-closed policy.

## Red flags — stop and reconsider

| You are about to… | Why it's wrong |
|---|---|
| Trust green CI on the private fork | There is no CI there. Test Tier-1 platforms locally. |
| Request the CVE while the patch is still in review | Request only after patch approved AND advisory text final. |
| Publish the advisory before merging/releasing | Publish last — after merge and any security release. |
| Skip the libparse-go release "at VMT discretion" | libparse-go is the mandatory exception; it MUST release. |
| Paste the advisory/patch into a web search | Embargoed. Public-info lookups only. |
| Use "Squash and merge" | Unavailable on advisories; squash manually before merge. |
| Apply labels / publish yourself | Recommend; the response lead applies unless delegated. |
