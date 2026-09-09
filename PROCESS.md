# Advisory handling process

This runbook describes how the security team triages and resolves an
advisory once it has been mirrored into this tracker. It is the
project-specific knowledge that does not live in any source repo.

> **AI-assisted triage.** A Claude Code skill library under `.claude/skills/`
> encodes this process for LLM sessions (including cheaper, smaller models) —
> start with `triaging-security-reports`; see [`CLAUDE.md`](CLAUDE.md)
> for the situation → skill map. The skills only ever **recommend** (verdicts,
> labels, draft replies) for a human to apply; they never post to or edit issues
> on their own. They complement this runbook — they do not replace it.

## Lifecycle

```
mirrored → triage → confirm → assess severity → assign CVE
        → coordinate fix → embargo & notify downstream → publish → backport → close
```

Two independent status axes — keep them distinct:

- **GHSA state** (machine-synced, objective): `triage → draft → published → closed`.
- **Our `status:*` label** (human-owned): our workflow position, which can lag
  the GHSA state (e.g. `published` upstream while we're still `fix-in-progress`
  on backports).

## Steps

### 1. Triage (issues arrive as `status:triage`; advance once done)
- Read the snapshot. **Ignore the reported severity** beyond using it as a hint.
- Decide validity. If invalid/dupe: `status:wontfix` or `status:duplicate`, comment why, close.
- If it's a valid bug but **not a security issue**, apply `not-a-security-issue`.
  This is a disposition label that sits on top of any `status:*`; the code fix,
  if any, is tracked via the linked PR. (Don't use `status:wontfix` — we may
  still fix it as an ordinary bug.)
- Apply `type:*` label(s). Flag `embargoed` if the report is under embargo.

### 2. Confirm
- Reproduce or otherwise confirm. Apply `status:confirmed`.

### 3. Assess severity (independent of the report)
- Compute our own CVSS and apply exactly one `sev:*` label.
- Record the CVSS vector and the assessed severity in the project fields.

### 4. CVE
- Request a CVE (GitHub can act as CNA via the advisory). Apply `cve-requested`,
  then `cve-assigned` once issued.

### 5. Coordinate the fix
- Track fix PRs in the affected source repo(s); link them in the issue.
- Apply `status:fix-in-progress`, then `status:fix-ready` when merged/awaiting release.

### 6. Embargo & downstream notification
- For embargoed issues, agree a disclosure date; record it in the project.
- Notify downstream consumers/packagers as appropriate before publication.

### 7. Publish
- Publish the GHSA upstream. Sync will flip GHSA state to `published` and comment.
- Apply `status:published`.

### 8. Backport & close
- Backport to supported release branches as needed.
- Close the tracker issue only when all follow-up is complete (sync does **not**
  auto-close). See *Open vs. closed* below.

## Open vs. closed

The GitHub issue's open/closed state is the "is this still live?" signal; the
status/disposition label records *why* it ended. The sync never opens or closes
issues — closing is a human action.

- **Open** — `status:triage`, `status:confirmed`, `status:fix-in-progress`,
  `status:fix-ready`: still needs attention.
- **Close** — terminal: `status:wontfix`, `status:duplicate`,
  `not-a-security-issue`, `status:fixed`. Close `status:published` once
  backports/follow-up are complete.
- **Close reason** — use *not planned* for wontfix/duplicate/not-a-security-issue;
  *completed* for fixed/published.
- The board's built-in **Item closed → Status: Done** workflow flips closed
  items to Done automatically; the label preserves the precise disposition.

## Project board

Repo-level Project, populated by the built-in **Auto-add to project** workflow
filtered on `label:advisory`.

Suggested custom fields: Assessed severity, Status, CVSS, CVE ID, GHSA ID,
Source repo, Affected versions, Fixed version, Embargo/disclosure date,
**Reported date**, Assignee.

**Reported date** (advisory creation date) and **Source repo** are the board
fields the sync writes automatically — both objective facts. Everything else is
human-filled.

Suggested views: Kanban by Status · grouped by Source repo · sorted by Assessed
severity · "Disclosure calendar" (Roadmap on Embargo date) · "Backlog age"
(Table sorted by Reported date ascending — oldest unresolved reports first).
