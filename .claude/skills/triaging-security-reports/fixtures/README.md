# Triage regression fixtures

These four Markdown files are **synthetic regression fixtures with known ground
truth** for exercising the `triaging-security-reports` process. They are **NOT
real reports** — do not file them, mirror them, or treat any of them as an
actual vulnerability. Each file ends with a `## GROUND TRUTH` section giving the
correct verdict; a triage run under test should **not** be shown that section.

The fixtures target the fictional `example-org/libparse` tree described in
`docs/security-reference/libparse-components.md`. When you adopt this tracker,
rewrite them against your own projects so the "exists / does not exist"
claims stay checkable by grepping a real clone.

Use them to check that a triage session reaches the right verdict, recommends
only legal labels, and drafts a courteous reply.

| Fixture | What it exercises | Correct verdict (ground truth) |
|---|---|---|
| `slop.md` | Nonexistent symbols / AI bug-bounty spam (CVSS 9.8, RCE framing). | **Fabricated** — files/functions don't exist → `status:wontfix`, close. Don't build the PoC. |
| `overstated.md` | Real code, real observation, **outside the threat model** (power analysis), pitched CRITICAL. | **Outside threat model** → `not-a-security-issue`; point to `SECURITY.md`; **not** critical, no `sev:*`, no `status:confirmed`. |
| `unsupported.md` | Real-looking bug in an **unsupported repo** (parse-playground). | **Unsupported project** → best-effort polite redirect; do NOT run CVE/advisory machinery; do not invent a `repo:*` label. |
| `genuine.md` | Coherent memory-safety bug in real code; mechanism hypothetical, unverifiable by reading alone. | **Credible — needs reproduction.** Do NOT dismiss as fabricated; do NOT mark `status:confirmed` without repro. |

Failure modes these guard against (see `../SKILL.md`): dismissing `genuine` as
fabricated (worst error — a missed real vuln), skipping the scope gate on
`unsupported`, inventing illegal labels, and confusing `status:wontfix` with
`not-a-security-issue`.
