#!/usr/bin/env bash
# Create the tracker's Project (v2) and its custom fields via gh.
#
# Usage:  ./scripts/setup-project.sh
# Edit OWNER / REPO below for your organization before running.
# Needs:  gh CLI with the 'project' scope:  gh auth refresh -s project
#         and org permission to create Projects.
#
# NOTE: two things have no API and must be done in the UI afterwards:
#   1. Project -> ... -> Workflows -> "Auto-add to project":
#        repository = example-org/security-tracking
#        filter     = is:issue label:advisory
#   2. Views/grouping, and renaming the built-in Status field's options to:
#        Triage / Confirmed / Fix in progress / Fix ready / Published / Done
set -euo pipefail

OWNER="example-org"
REPO="example-org/security-tracking"
TITLE="Security advisories"

NUM=$(gh project create --owner "$OWNER" --title "$TITLE" --format json --jq '.number')
echo "Created project #$NUM"

gh project link "$NUM" --owner "$OWNER" --repo "$REPO"
echo "Linked to $REPO"

field() {
  local name="$1" type="$2" opts="${3:-}"
  if [[ -n "$opts" ]]; then
    gh project field-create "$NUM" --owner "$OWNER" --name "$name" \
      --data-type "$type" --single-select-options "$opts" >/dev/null
  else
    gh project field-create "$NUM" --owner "$OWNER" --name "$name" \
      --data-type "$type" >/dev/null
  fi
  echo "  + field: $name ($type)"
}

field "Assessed severity" SINGLE_SELECT "Critical,High,Medium,Low"
field "Source repo"       SINGLE_SELECT "libparse,parse-server"
field "CVSS"              TEXT
field "CVE ID"            TEXT
field "GHSA ID"           TEXT
field "Affected versions" TEXT
field "Fixed version"     TEXT
field "Embargo / disclosure date" DATE
field "Reported date"     DATE   # auto-populated by the sync (objective fact)

echo
echo "Project number: $NUM"
echo "Set this so the sync can write the Reported date field:"
echo "  gh variable set PROJECT_NUMBER --body $NUM --repo $REPO"
echo
echo "Finish in the UI:"
echo "  1. Workflows -> Auto-add to project: repo=$REPO, filter='is:issue label:advisory'"
echo "  2. Rename Status options + create the views (see PROCESS.md),"
echo "     including a 'Backlog age' view: Table sorted by Reported date (ascending)."
