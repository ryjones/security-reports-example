# Skill library for security-tracking — design

**Goal:** A `.claude/skills/` library that lets junior/mid-level engineers and
smaller, cheaper models run the organisation's vulnerability-response workflow
in this repo at the standard of a senior team member — especially triaging the
incoming report volume, much of which is AI slop or overstates security impact.

> This is the design note for the **example** library in this repository. The
> projects it names (`libparse`, `parse-server`) are fictional; the approach is
> not.

## Context

- This private repo mirrors GitHub Security Advisories from the repos in
  `sources.yml` as issues (machine-owned snapshot region + human area).
- [PROCESS.md](../../PROCESS.md) defines the label lifecycle; the canonical
  response process lives in the governance repo
  (`governance/security/response-process.md`).
- Upstream ground truth: each source repo's `SECURITY.md` (threat model,
  supported versions), `PLATFORMS.md` (tiers), per-module docs (constant-time
  claims), and the published advisory pages. Dated snapshots of these live in
  `docs/security-reference/`.
- Pain points to solve: (1) hallucinated/LLM-generated reports that name
  nonexistent symbols or incoherent PoCs; (2) real-but-out-of-threat-model
  reports pitched as "critical"; (3) small team, big queue — cheap-model
  sessions must do reliable first-pass triage.

## Approach

Eight skills, one routing `CLAUDE.md`. Authored and reviewed in stages:
research pack of verified facts → RED baseline scenarios (watch small-model
agents fail without skills) → parallel authoring → adversarial fact-check +
compliance review → GREEN re-test with small-model agents → loophole fixes.

Alternatives considered: (a) one mega-skill — rejected: too long to load,
poor discovery, mixes reference with discipline; (b) prompts-in-docs (no
skills) — rejected: not discoverable by Claude Code sessions, no trigger
conditions; (c) automation (a GitHub Action that auto-triages) — out of scope,
but the triage skill's output format is designed so it could later feed one.

## The skills

| Skill | Type | Job |
|---|---|---|
| `triaging-security-reports` | workflow (flagship) | End-to-end first-pass triage of a tracker issue: parse claims → verify every claim against source → scope check → severity reality-check → assessment verdict → recommended labels + draft response. Evidence-before-assertion discipline. |
| `detecting-report-slop` | technique | Verification protocol + rubric for LLM-generated/fabricated reports (nonexistent symbols, wrong paths, CVSS walls, incoherent PoC). Every named symbol gets grepped. |
| `threat-model-and-scope` | reference | What is/isn't in scope: the threat model, the security-support boundary (core library in full; server and bindings lock-step), supported-versions policy, module and platform tiers, upstream-code policy, common out-of-scope patterns. |
| `assessing-severity` | technique | Independent CVSS assessment with project-specific attacker-model guidance; maps to `sev:*`. Counters severity inflation with concrete scoring rules and anchors from published advisories. |
| `reproducing-security-reports` | technique | Build/repro recipes: sanitizer builds, known-answer vectors, constant-time tests, the network path through the server; minimal-harness patterns; when repro is/isn't required. |
| `responding-to-reporters` | technique | Response templates per assessment outcome; courteous-but-firm slop rejection; acknowledgement SLA; embargo language; what never to promise. |
| `operating-the-tracker` | reference | Label taxonomy semantics, status transitions, snapshot-region rules, `gh` command recipes, board fields, open-vs-closed policy. |
| `coordinating-fix-and-disclosure` | reference | Post-confirmation phases: advisory draft, private fork, CVE via GitHub as CNA, embargo, publish, lock-step releases, feedback report. |

Cross-references: triage is the entry point and links to the others.
`CLAUDE.md` routes: "new advisory issue → triaging-security-reports", etc.

## Non-negotiable content rules

- **Confidentiality:** skills must forbid pasting embargoed report content
  into web searches or external services. Public-info lookups only.
- **Grounding:** every factual claim (paths, commands, labels, versions,
  process steps) is verified against the local clones / this repo during
  review. Version-specific facts must be phrased as "check `SECURITY.md`",
  not hardcoded, wherever staleness is likely.
- **Skepticism without cynicism:** the failure mode of a slop-filter is
  rejecting a true positive. Triage/slop skills must include the
  "don't reject everything" counterweight and escalation paths to humans.
- **Human-owned judgment stays human:** skills produce *recommendations*
  (labels, verdicts, drafts) for a human to apply unless the operator
  explicitly delegates the action. Matches README's automation/human split.
- Skills use `Use when...` descriptions (triggers only, no workflow
  summaries), token-lean bodies, and reference tables in supporting files
  where heavy.

## Testing

Fixture reports with known ground truth live under
`.claude/skills/triaging-security-reports/fixtures/`: (1) slop with
nonexistent symbols; (2) real code, out-of-threat-model, pitched critical;
(3) plausible genuine memory-safety bug (must NOT be rejected); (4) report
against an unsupported project.
RED: small-model subagents triage fixtures without skills — record failures.
GREEN: same scenarios with skills — verdicts must match ground truth, labels
must be legal, drafts courteous. Refactor until pass.
