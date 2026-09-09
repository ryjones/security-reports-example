# Reply templates (responding-to-reporters)

Drafts for a **human VMT member to review and send**. Adapt freely; always keep
the universal rules from SKILL.md (thank; no timelines/CVEs/bounties promised;
no private links or other reports; match the channel; don't apologize). Fill
`[…]`. Never paste any of this into an external service — the repo is
embargo-sensitive.

Templates map to the VMT assessment outcomes in
`governance/security/response-process.md` (Assessment phase).

---

## Acknowledgement (Intake, within 1–2 days)

> Thank you for reporting this to the example-org project. We have received
> your report and a member of our Vulnerability Management Team is looking into
> it. We will follow up once we have completed our assessment.

No verdict, no severity, no timeline at this stage.

---

## Request for a runnable PoC (report references real code, mechanism unproven)

> Thank you for your report. To assess the described behavior we would like to
> reproduce it. Could you share a minimal, self-contained proof-of-concept
> (source plus the exact build flags and steps, and the input frame if there is
> one) that triggers the issue against [current release / `main`]? That will
> let us confirm the mechanism and scope.

---

## Vulnerability confirmed

> Thank you for this report — we have confirmed it is a security issue and are
> handling it under our coordinated disclosure process. If you would like to
> review or contribute to the fix, we would welcome that. Please also let us know
> your preference on public credit, and whether you have any disclosure-timing
> constraints on your end.

No CVE promise, no fixed date. The offer of involvement comes from
response-process.md ("Responding to the reporter"); the credit and
disclosure-timing questions are project good practice, not required by it.

---

## Working as intended

> Thank you for your report. After review, the behavior you describe is the
> intended behavior of the library, because [specific reason]. We do not consider
> it a security issue. If you think this behavior could be improved, you are very
> welcome to open a feature request on the public [libparse / parse-server]
> tracker.

Explain the reasoning — the VMT may have misread the report, and the explanation
invites correction (response-process.md).

---

## Bug (real, but not a security issue)

> Thank you for your report. We looked into this and believe it is a genuine but
> non-security bug: [one line]. Since it does not have security impact, could you
> refile it as a regular issue on the public [libparse / parse-server] tracker so
> it can be handled in the open? We appreciate you flagging it.

---

## Feature request

> Thank you for the suggestion. The current behavior is intended, so we are
> closing this as a security report. If you would like to see this changed, please
> open a feature request on the public [project] tracker.

---

## Out of scope — outside the threat model

> Thank you for your report. The issue you describe falls outside the libparse
> threat model — see the threat model in libparse `SECURITY.md`: [one-line why,
> e.g. it requires same-physical-system access / power or EM observation]. We
> may still consider a best-effort improvement, but we are not able to commit to
> a fix or a timeline. We appreciate you taking the time to investigate.

Point to the authoritative `SECURITY.md`; make no fix commitment. Recommend the
`not-a-security-issue` disposition if it is nonetheless a real code observation
(see operating-the-tracker), reserving `status:wontfix` for "no action at all."

---

## Out of scope — upstream / unsupported subproject

> Thank you for your report. This affects [upstream project / a repository
> without security support, e.g. parse-playground], which is outside the
> security-support scope described in `governance/security/response-process.md`.
> We would encourage you to report it to [upstream / that project's tracker] at
> [link if public], and we are happy to help you route it. We may pick up a
> best-effort fix but cannot commit to one.

Offer to help refile upstream (response-process.md, Out-of-scope sub-table).

---

## Fabricated / unverifiable existence claims

> Thank you for your report. We reviewed the referenced code paths: [the named
> functions / files / symbols] do not exist in [libparse / parse-server], so we
> are unable to act on this report. If you have a runnable proof-of-concept
> against a current release, we would be glad to look again.

Factual and non-accusatory. Name exactly which load-bearing symbols/paths failed
to exist. **Never mention AI/LLMs, never imply bad faith, never be snarky, do not
debate — one round and close.** Distinguish from *mixed* reports (some real
symbols): those get the request-for-PoC template, not this one.
