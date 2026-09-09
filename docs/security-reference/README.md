# Security reference pack

Distilled, **dated snapshots** of ground-truth facts about the source projects
this tracker watches, produced to support the skill library under
`.claude/skills/`. Skills cite these for convenience, but the **authoritative
source is always the live file** each snapshot points to (`SECURITY.md`,
`PLATFORMS.md`, the module docs in the source repo, the governance repo's
response process, and the published advisory pages). Version- and
release-specific facts here drift — re-derive before relying on them.

> **This is an example.** The projects described here — `example-org/libparse`
> and `example-org/parse-server` — are fictional. Their file names, functions,
> build options, advisories and CVE numbers are invented so the skills and the
> triage fixtures have something concrete and self-consistent to cite. When
> you adopt this tracker, replace every file in this directory with snapshots
> of **your** projects, and keep the same shape: a security policy, a component
> overview, the network-exposure story, the response process mapped onto the
> tracker's labels, reproduction recipes, and a calibration table of your own
> published advisories.

Paths written `../libparse`, `../parse-server`, `../governance` assume the
companion repos are checked out as siblings of this repo (see the root
`CLAUDE.md`).

| File | What it snapshots |
|---|---|
| `libparse-security.md` | Threat model, supported-versions policy, reporting channels, platform tiers, constant-time test locations. |
| `libparse-components.md` | Per-module overview: public API, constant-time claims, default-off modules, upstream sources. |
| `parse-server.md` | Network attack surface: how a libparse bug becomes reachable over the wire. |
| `process.md` | The VMT response process mapped onto this tracker's label lifecycle; snapshot-region rules. |
| `repro.md` | Build / test / reproduction recipes for libparse and parse-server. |
| `past-advisories.md` | Published advisories with CVSS vectors — the severity-calibration anchors. |
