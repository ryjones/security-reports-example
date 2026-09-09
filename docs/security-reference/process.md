# Vulnerability response process & tracker conventions (example fact pack)

Verified against the cited files on 2026-07-10. Where content is
version-dependent, the authoritative file is named instead of hardcoding
values. **Fictional example content**: `example-org` and its governance repo
are invented; the process itself follows the public
[OpenSSF vulnerability-disclosure guide](https://github.com/ossf/oss-vulnerability-guide)
and is a reasonable starting point for any project.

Sources read in full:
- `../governance/security/response-process.md` (the organisation's process)
- `../governance/security/reports/YYYYMMDD-template.md` (post-mortem template)
- `./PROCESS.md` (tracker runbook), `./README.md`
- `./scripts/setup-labels.sh` (label taxonomy)
- `./scripts/sync_advisories.py` (sync behaviour)
- `./.github/ISSUE_TEMPLATE/security-advisory.yml`, `./sources.yml`
- `../governance/config.yaml` (VMT membership: the `security-managers` team)

---

## Part 1 — The coordinated vulnerability disclosure process

Source: `governance/security/response-process.md`. It follows the OpenSSF
guide's phases, with one added phase ("Feedback"). It does not apply to
releases that predate its adoption.

### Scope (which projects have security support)

- The process applies in full to **libparse**.
- **parse-server**, **libparse-python** and **libparse-go** are in the
  security-support set in *lock-step*: their `main` tracks libparse `main`,
  they build against libparse versions marked supported in libparse
  `SECURITY.md`, and a same-CVE advisory (and, at VMT discretion, a release)
  is cut alongside each libparse security release. `libparse-go` must always
  get a new tagged release because it pins a libparse version.
- Other repositories (`parse-playground`, `parse-cli`, anything else) have
  **no security support**; fixes are best-effort.
- Scope may grow; an in-scope repo references the process from its
  `SECURITY.md` and documents platform support in a `PLATFORMS.md`.

### Vulnerability Management Team (VMT) and response lead

- The VMT responds to security reports for the organisation's software.
- Membership is the `security-managers` team in `governance/config.yaml` —
  that file is authoritative; never hardcode names elsewhere.
- Members rotate on-call at each governance meeting; the on-call member is
  confirmed and communicated there. Members back each other up.
- **Response lead**: the on-call member who acknowledges a report owns the
  whole response to it, end to end.

### Phase 1 — Intake

Begins when a report is received; ends when a VMT member acknowledges it and
becomes response lead.

- Endorsed channels: (1) email to **security@example.org**; (2) a GitHub
  Security Advisory on the affected repo.
- Acknowledge promptly (OpenSSF recommends within 1–2 days). Email → reply
  cc'ing security@example.org; GHSA (arrives in "Triage") → comment on it.
- Acknowledgement carries no assessment.
- **Internal reports** from maintainers may skip straight to Patching at VMT
  discretion.
- Reports via other channels are funnelled into an endorsed one by whoever
  notices; do not force the reporter to resubmit.

### Phase 2 — Assessment

Begins at acknowledgement; ends when the VMT responds with an assessment.

- The response lead appoints **domain expert(s)** (may be themselves).
- Assessment outcomes:

| Assessment | Response |
|---|---|
| Working as intended | Tell the reporter it is intended; they may file a feature request. Close. Explain the reasoning in case the VMT misread the report. |
| Bug | Unwanted behaviour but not a security issue; ask them to refile publicly. Close. |
| Feature request | Intended behaviour; they may file a feature request. Close. |
| Vulnerability | Confirmed security issue. Proceed. |
| Out of scope | Out of scope for the organisation; help refile upstream if applicable. See sub-table. |

- **Out-of-scope sub-table** (the organisation vendors some upstream code —
  the SHA-256 implementation — and assumes no obligation to fix upstream
  defects, though it may do so best-effort; pass upstream reports on; if a
  local patch ships while upstream stays unfixed, the advisory must say so):

| "Out of scope" assessment | Description | Additional action |
|---|---|---|
| Outside threat model | Outside the documented threat model. | Decide whether severity warrants a patch regardless. |
| Unsupported project | In a repo without security support. | Decide whether to patch anyway; if not, document in that repo. |
| Unable to assess | Needs upstream domain knowledge the VMT lacks. | Monitor upstream. |
| Vulnerability: can patch | Real, simply patchable locally. | Decide whether to patch; coordinate disclosure with upstream. |
| Vulnerability: can't patch | Real, not simply patchable locally. | Coordinate with upstream; monitor; depending on severity, consider dropping the dependency. |

- **Responding to the reporter**: always courteous, always thank them; if a
  patch will be made, offer them a chance to review or contribute.
- **Response team** (for a vulnerability to patch): patch developer(s) plus
  **at least two maintainers with write permission** on the affected repo,
  plus one person with GitHub admin available.

### Phase 3 — Patching

- Create a **draft GHSA** on the affected repo (flip an existing one from
  Triage to Draft, or create fresh). Add the response team; add the reporter
  if they want in.
- Use the advisory's **private fork** for the fix; open the PR from it.
- **No CI on private forks** → the patch must be tested locally on all
  **Tier 1 platforms** (see libparse `PLATFORMS.md`) plus any lower-tier
  platform explicitly affected. Add a regression test where possible.
- Approval: at least two response-team members with write permission, plus
  the reporter if involved. Squash manually after approval ("Squash and
  merge" is unavailable on advisory PRs).
- If tests fail on a lower-tier platform, the VMT may drop that platform's
  support to expedite a Tier 1 release.
- The domain expert finalises the advisory text, including a **CVSS** vector.

### Phase 4 — CVE assignment

Once the patch is approved and the advisory text is final, the response lead
requests a CVE from within the draft advisory (GitHub acts as CNA).

### Phase 5 — Public disclosure

- Merge the advisory (needs a GitHub admin; may need to override branch
  protection).
- Publish a security release if warranted (VMT discretion).
- Add patch specifics (commit hash, versions) to the advisory text.
- Publish the advisory — **only after** the patch is merged and any release
  is out.
- Announce on **security-announce@example.org**.
- Publish same-CVE advisories on parse-server and the bindings; `libparse-go`
  always gets a release.

### Phase 6 — Feedback

The response lead files a post-mortem in
`governance/security/reports/YYYYMMDD-<name>.md` from the template,
dated by report creation. It records process friction, not technical detail.
Optional if work stopped at Assessment.

---

## Part 2 — This tracker

A **private, embargo-sensitive** repo. Per `governance/config.yaml` the
tracker is private with admin for the org admins and write for
`security-managers` and the maintainer teams of the watched repos.

### Architecture (README.md)

- `sources.yml` lists watched repos with a `label:` and a `tag:` each.
  Authoritative and expected to grow — read it, never hardcode.
- `.github/workflows/sync-advisories.yml` runs hourly and one-way-mirrors
  each source repo's GHSAs into issues via `scripts/sync_advisories.py`. It
  never writes back.
- Each mirror issue = machine-owned **snapshot region** + human-owned tail.
- Sync auth: repo secret `ADVISORY_SYNC_TOKEN`, a fine-grained PAT with
  Security advisories: read on the sources, Issues: read-write on the
  tracker, and org Projects: read-write if `PROJECT_NUMBER` is set.

### Two independent status axes (PROCESS.md)

- **GHSA state** — machine-synced: `triage → draft → published → closed`.
- **`status:*` label** — human-owned workflow position; may lag GHSA state.

### Complete label taxonomy (scripts/setup-labels.sh is authoritative)

| Label | Description | Owner |
|---|---|---|
| `advisory` | Mirror of an upstream advisory | machine |
| `withdrawn` | Upstream advisory withdrawn | machine |
| `repo:libparse`, `repo:parse-server` | Affected source repo (must match `sources.yml`) | machine, on creation |
| `sev:critical` / `sev:high` / `sev:medium` / `sev:low` | Our assessed severity | human, never auto-applied |
| `status:triage` | Awaiting/under triage | sync sets on creation only; humans own all later transitions |
| `status:confirmed` | Confirmed valid security issue | human |
| `status:fix-in-progress` | Fix being developed | human |
| `status:fix-ready` | Fix merged, pending release | human |
| `status:published` | Advisory published | human |
| `status:fixed` | Fixed and closed, no advisory published | human |
| `status:wontfix` | Will not act | human |
| `status:duplicate` | Duplicate of another advisory | human |
| `type:memory-safety` | Memory-safety issue | human |
| `type:side-channel` | Timing / side-channel issue | human |
| `type:logic-flaw` | Authentication / validation / correctness flaw | human |
| `type:supply-chain` | Build / dependency / supply-chain issue | human |
| `type:upstream` | Inherited from vendored upstream code | human |
| `embargoed` | Under embargo | human |
| `cve-requested` / `cve-assigned` | CVE lifecycle | human |
| `not-a-security-issue` | Valid report, not a security issue (may still be fixed as a normal bug); a disposition atop any `status:*` | human |

Rules: exactly one `sev:*`; one `status:*` at a time; `type:*` may repeat;
`repo:*` must match `sources.yml`.

### What the sync does / never does (scripts/sync_advisories.py)

Markers: `<!-- ghsa-sync-meta {...} -->` (start; JSON with `ghsa`, `state`,
`updated_at`) and `<!-- /ghsa-sync -->` (end). Everything through the end
marker is overwritten each run; everything after is never touched.

The sync **does**: read GHSAs from every repo in `sources.yml`; create
issues titled `[<tag>] <summary>` with labels `advisory`, `status:triage`
and the `repo:*` label (plus `withdrawn` if applicable) and a body of
snapshot + `### Triage` checklist; on upstream change, rewrite the snapshot,
preserve the tail, and post a `🔄` comment; write the board's **Reported
date** and **Source repo** fields if `PROJECT_NUMBER` is set.

The sync **never**: writes to a source GHSA; opens or closes issues; changes
`sev:*` / `status:*` / `type:*` / `embargoed` / `cve-*` after creation;
maps reported severity onto `sev:*`; edits below the end marker; writes any
other board field.

### Manual-intake template

"Security advisory (manual)" — only for reports that did **not** arrive as a
GHSA. Auto-labels `advisory` + `status:triage`. Do not set `sev:*` or
`status:*` from the reporter's claim.

### Tracker lifecycle and runbook (PROCESS.md)

```
mirrored → triage → confirm → assess severity → assign CVE
        → coordinate fix → embargo & notify downstream → publish → backport → close
```

See `PROCESS.md` for the eight steps and the open-vs-closed policy (keep
`triage`/`confirmed`/`fix-*` open; close `wontfix`/`duplicate`/
`not-a-security-issue`/`fixed` and, after follow-up, `published`; close
reason *not planned* vs *completed*).

---

## Part 3 — Process phases → tracker labels

| Phase | GHSA state (machine) | Tracker `status:*` / labels (human) |
|---|---|---|
| 1. Intake | `triage` | `status:triage` (set by sync, or by the manual template) |
| 2. Assessment | `triage` | `status:triage` → `status:confirmed` + one `sev:*` + `type:*` (+ `embargoed`). Non-vulnerability outcomes exit here: `status:wontfix`, `status:duplicate`, or `not-a-security-issue`; close as *not planned*. |
| 3. Patching | `draft` | `status:fix-in-progress` → `status:fix-ready` |
| 4. CVE | `draft` | `cve-requested` → `cve-assigned` |
| 5. Disclosure | `published` | `status:published`; keep open through backports, then close *completed*. `status:fixed` covers fixed-with-no-advisory. |
| 6. Feedback | — | No label; post-mortem in the governance repo. |

Invariants: never trust reported severity; status is a single human-owned
axis; never edit inside the snapshot region; closing is always human.
