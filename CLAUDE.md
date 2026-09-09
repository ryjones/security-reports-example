# security-tracking

This is the **private, embargo-sensitive** advisory tracker for `example-org`.
It mirrors GitHub Security Advisories from **libparse** and **parse-server**
as issues (a machine-owned snapshot region synced hourly, plus a human working
area). Its job: triage incoming reports — much is AI-generated slop or
overstated — and coordinate confirmed fixes, CVEs, and disclosure.

> This repository is a public **example**. The projects, advisories, people and
> identifiers in it are fictional. See `README.md` → "Adapting this template".

**Confidentiality:** Report contents, advisory drafts, and reporter identities
are embargoed. Never paste them into web searches or any external service —
public-info lookups only. Reported severity is never trusted; recompute it.

## Roles

The **Vulnerability Management Team (VMT)** owns the response process. The
**response lead** is the on-call VMT member who acknowledged a report and owns
its response end to end; skills that draft replies or coordinate fixes speak on
the response lead's behalf.

## Companion repositories

**libparse**, **parse-server**, and **governance** (the process repo; key file
`governance/security/response-process.md`) are separate `example-org` repos.
Skills name them and assume clones as siblings of this repo (`../libparse`,
`../parse-server`, `../governance`), or read them on GitHub — verify facts
against the local checkout. `docs/security-reference/` holds dated snapshots;
always name the live authoritative file alongside them.

## Which skill to use

| Situation | Skill |
|---|---|
| New/untriaged advisory issue, or "triage this report" | **triaging-security-reports** (entry point) |
| Judging whether a report is fabricated / LLM-generated | **detecting-report-slop** |
| "Is X in scope / in the threat model?"; supported projects & versions | **threat-model-and-scope** |
| Assigning `sev:*` / CVSS; sanity-checking a claimed severity | **assessing-severity** |
| Confirming a credible report; running a PoC safely | **reproducing-security-reports** |
| Drafting any reply to a reporter | **responding-to-reporters** |
| Applying labels/status, board fields, `gh` recipes, snapshot rules | **operating-the-tracker** |
| Post-confirmation: advisory, CVE, embargo, disclosure, backports | **coordinating-fix-and-disclosure** |

Start with **triaging-security-reports**; it invokes the others as sub-skills.
Skills produce **recommendations** (labels, verdicts, drafts) — act only when an
operator delegates it.

See `PROCESS.md` for the label lifecycle and open-vs-closed policy, and
`README.md` for the human/machine split.

## Two iron rules

1. **Never hand-edit a mirror issue's machine-owned snapshot region** (above the
   sync marker) — the hourly sync overwrites it. Humans work below it / in
   comments.
2. **Never paste report or advisory content into any external service** —
   embargoed material stays in this repo.
