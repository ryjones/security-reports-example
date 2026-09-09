#!/usr/bin/env bash
# Create / update the label taxonomy for this tracker repo. Idempotent.
#
# Usage:  ./scripts/setup-labels.sh [owner/repo]
# Needs:  gh CLI, authenticated with repo admin on the tracker repo.
#
# repo:* labels must match the `label:` values in sources.yml.
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Applying labels to $REPO"

# name|color|description
LABELS=(
  # --- machine-managed ---
  "advisory|5319e7|Mirror of an upstream security advisory (managed by sync)"
  "withdrawn|cccccc|Upstream advisory was withdrawn"

  # --- source repo (keep in sync with sources.yml) ---
  "repo:libparse|0e8a16|Affects libparse"
  "repo:parse-server|0e8a16|Affects parse-server"

  # --- assessed severity (HUMAN-OWNED; do not auto-apply) ---
  "sev:critical|b60205|Our assessed severity: critical"
  "sev:high|d93f0b|Our assessed severity: high"
  "sev:medium|fbca04|Our assessed severity: medium"
  "sev:low|0e8a16|Our assessed severity: low"

  # --- workflow status (HUMAN-OWNED, except the initial status:triage which
  #     the sync sets on creation; humans own every transition after that) ---
  "status:triage|ededed|Awaiting/under triage (initial status, set by the sync)"
  "status:confirmed|c2e0c6|Confirmed valid"
  "status:fix-in-progress|fbca04|Fix being developed"
  "status:fix-ready|0e8a16|Fix ready / merged, pending release"
  "status:published|1d76db|Advisory published"
  "status:fixed|0e8a16|Fixed/resolved and closed (no advisory published)"
  "status:wontfix|ffffff|Will not fix"
  "status:duplicate|cfd3d7|Duplicate of another advisory"

  # --- type ---
  "type:memory-safety|e99695|Memory-safety issue"
  "type:side-channel|e99695|Timing / side-channel issue"
  "type:logic-flaw|e99695|Authentication / validation / correctness flaw"
  "type:supply-chain|e99695|Build / dependency / supply-chain issue"
  "type:upstream|e99695|Inherited from an upstream / reference implementation"

  # --- disclosure ---
  "embargoed|000000|Under embargo; handle with care"
  "cve-requested|5319e7|CVE has been requested"
  "cve-assigned|5319e7|CVE has been assigned"

  # --- disposition (applies on top of any status) ---
  "not-a-security-issue|1d76db|Valid report determined not to be a security issue (may still be fixed as a normal bug)"
)

for entry in "${LABELS[@]}"; do
  IFS='|' read -r name color desc <<< "$entry"
  if gh label create "$name" --color "$color" --description "$desc" --repo "$REPO" 2>/dev/null; then
    echo "  + $name"
  else
    gh label edit "$name" --color "$color" --description "$desc" --repo "$REPO" >/dev/null
    echo "  ~ $name"
  fi
done
echo "Done."
