# security-tracking — example advisory tracker

> **This repository is an example.** It shows how to run a private,
> embargo-sensitive vulnerability tracker for a small organisation with an
> AI-assisted triage skill library. Every project, person, advisory and CVE
> number in it is fictional (`example-org/libparse`, `example-org/parse-server`,
> `GHSA-exmp-*`, `CVE-20xx-9000x`). See [Adapting this template](#adapting-this-template).

> ⚠️ **A real deployment must be a private repository.** Issues mirror
> unpublished security advisories. Do not share contents, screenshots, or
> links outside the authorised security team.

Central tracker for security advisories across an organisation's repositories.
Each upstream [GitHub Security Advisory (GHSA)][ghsa] is mirrored here as an
issue for discussion, tagging, and status tracking, and surfaced on a project
board. A skill library under `.claude/skills/` lets Claude Code sessions run
first-pass triage to the same standard as a senior team member — recommending
verdicts, labels and reply drafts that a human applies.

[ghsa]: https://docs.github.com/en/code-security/security-advisories

## How it works

- **`sources.yml`** lists the repos we watch. Add a repo with a one-line PR.
- **`.github/workflows/sync-advisories.yml`** runs hourly and one-way-mirrors
  each source repo's advisories into issues here via
  [`scripts/sync_advisories.py`](scripts/sync_advisories.py). It never writes
  back to a source advisory.
- Each mirror issue has a machine-owned **snapshot region** (overwritten on
  every sync) and a human-owned area below it (never touched).
- After each sync, [`.github/actions/report-status.zsh`](.github/actions/report-status.zsh)
  renders the whole backlog from the mirror issues into
  [`reports/advisory-backlog.md`](reports/advisory-backlog.md) and proposes it
  as a pull request (never pushed straight to the default branch).

### What automation does and does not touch

| Automation owns (objective facts) | Humans own (judgment) |
|---|---|
| Snapshot body, GHSA state, reported severity/CVSS *(shown as unverified)* | All discussion below the snapshot marker |
| `advisory`, `repo:*`, `withdrawn` + the initial `status:triage` | `sev:*`, every `status:*` transition, `type:*`, `embargoed`, `cve-*` labels |
| Board **Reported date** + **Source repo** fields (objective) | All other board fields (Assessed severity, Status, CVSS, Embargo date…) |

**Reported severity is never trusted.** It is displayed for reference only and
never mapped onto our `sev:*` labels — a human assesses and labels each issue.
See [PROCESS.md](PROCESS.md).

**Status** is a single axis. Every issue is created as `status:triage`; from
there a human moves it (confirmed → fix-* → published, or a terminal
wontfix/duplicate/fixed). The sync sets only that initial value and never
changes a status afterwards.

### AI-assisted triage

`.claude/skills/` holds eight skills — triage entry point, slop detection,
scope, severity, reproduction, reporter replies, tracker mechanics, and fix
coordination — plus four regression fixtures with known ground truth.
[`CLAUDE.md`](CLAUDE.md) routes a situation to a skill. The skills only ever
**recommend**; they never post to or edit issues on their own. The design
rationale is in [`docs/design/skill-library.md`](docs/design/skill-library.md)
and the fact packs they cite are in [`docs/security-reference/`](docs/security-reference/).

## Setup (one-time)

1. **Repo must be private** with access limited to the security team.
2. **Labels:** `./scripts/setup-labels.sh` (needs `gh`, repo admin). Do this
   before the first non-dry-run sync — the sync expects the labels to exist.
3. **Sync token** — see [Creating the sync token](#creating-the-sync-token).
4. **Project board:** `./scripts/setup-project.sh` creates the Project + custom
   fields and links it to the repo. Then, in the UI, add the built-in
   **Auto-add to project** workflow filtered on `label:advisory`, rename the
   Status options, and create the views (see [PROCESS.md](PROCESS.md)). Finally
   set the repo variable so the sync can write the board's **Reported date**:
   ```
   gh variable set PROJECT_NUMBER --body <number printed by setup-project.sh> \
     --repo example-org/security-tracking
   ```
   Leave `PROJECT_NUMBER` unset to skip board writes entirely.
5. **Report PR:** enable *Allow GitHub Actions to create and approve pull
   requests* (Settings → Actions → General) so the report job can open its PR.
6. **Smoke-test:** run **Actions → Sync security advisories → Run workflow**
   with *dry run* ticked and confirm the log lists advisories and prints
   `[dry-run] CREATE …`. Then run again without dry run to create the issues.

### Creating the sync token

A fine-grained PAT is owned by an individual account, so it can only see
advisories on repos where that account has **admin** or **security-manager**
access. Prototype with your own PAT; move to a dedicated bot account or a
GitHub App before depending on it (see [token ownership](#token-ownership)).

**a. Generate the PAT** — github.com → Settings → Developer settings →
Personal access tokens → Fine-grained tokens →
[Generate new token](https://github.com/settings/personal-access-tokens/new):

- **Resource owner:** your organisation (*not* your personal account).
- **Expiration:** pick a date (max 1 year) and set a rotation reminder.
- **Repository access → Only select repositories:** the source repos
  (`libparse`, `parse-server`) **and** this tracker repo.
- **Permissions** (each applies where relevant):
  - Repository → **Security advisories: Read-only** (read source advisories)
  - Repository → **Issues: Read and write** (create issues here)
  - Organization → **Projects: Read and write** (write the board's Reported
    date field; omit if you leave `PROJECT_NUMBER` unset)
  - everything else: *No access*.
- Generate and **copy the token immediately** — it is shown only once.

**b. Approval (maybe)** — if the org restricts fine-grained PATs, the token
shows *pending* and the sync 403s until an org owner approves it under
Org → Settings → Third-party Access → Personal access tokens.

**c. Store it** as the repo secret **`ADVISORY_SYNC_TOKEN`**:

```
gh secret set ADVISORY_SYNC_TOKEN --repo example-org/security-tracking
```

or via Settings → Secrets and variables → Actions → New repository secret.

> If the token can't list a source repo's `triage`/`draft` advisories, the
> owning account lacks admin/security-manager on that repo — the token will
> be valid but return nothing for it.

### Token ownership

A personal PAT carries your identity and breaks if your access changes or you
leave, and it expires within a year. For anything you depend on, prefer a
dedicated **bot account** added to the org as a security manager, or a
**GitHub App** installed on the org. Swapping later changes nothing in this
repo — the workflow just reads `secrets.ADVISORY_SYNC_TOKEN`.

## Adding a source repo

Append to [`sources.yml`](sources.yml), add a matching `repo:<name>` label in
`setup-labels.sh`, add the name to the **Source repo** field options in
`setup-project.sh`, and open a PR.

## Adapting this template

Everything fictional lives in a handful of places. To point the tracker at
your own projects:

1. **`sources.yml`** — your repos, labels and title tags.
2. **`scripts/setup-labels.sh`** — matching `repo:*` labels; adjust the
   `type:*` taxonomy to your domain.
3. **`scripts/setup-project.sh`** — `OWNER`, `REPO`, the Source repo options.
4. **`.github/ISSUE_TEMPLATE/`** — the contact links and repo placeholders.
5. **`.github/workflows/sync-advisories.yml`** — the bot identity used for the
   report PR.
6. **`docs/security-reference/`** — replace every fact pack with snapshots of
   your projects' `SECURITY.md`, platform tiers, module docs, build recipes,
   response process, and **published** advisories. This is what grounds the
   skills; keep the same shape.
7. **`.claude/skills/`** — search for `libparse`, `parse-server`,
   `example-org`, `example.org` and the `GHSA-exmp-*` / `CVE-20xx-9000x`
   identifiers and substitute your own. The triage fixtures under
   `triaging-security-reports/fixtures/` must be rewritten against your real
   source tree so their ground truth holds.
8. **`CLAUDE.md`** and **`PROCESS.md`** — the project names and the governance
   repo path.

The sync script, the report renderer and the workflow are project-agnostic and
need no changes beyond the items above.
