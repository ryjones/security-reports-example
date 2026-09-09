#!/usr/bin/env zsh
#
# report-status.zsh — render the advisory backlog as GitHub-flavored
# markdown, built entirely from the mirror issues in this tracker repo.
#
# Earlier revisions of this script swept /orgs/{org}/security-advisories and
# probed each repo's private-vulnerability-reporting switch. Both need an org
# owner / security-manager / repo-admin token, which the sync workflow does not
# have — and both are redundant here, because scripts/sync_advisories.py has
# already mirrored every GHSA into an issue whose machine-owned snapshot region
# carries the source repo, GHSA id, CVE, upstream state, reported severity and
# dates. So this reads issues instead: it needs only Issues:read, it also picks
# up manually filed reports that never had a GHSA (private email reports), and
# it can show what the advisory API cannot — the VMT's own triage state, from
# the sev:* / status:* / type:* labels.
#
# Strictly read-only: every call is a GET. This never creates, edits, labels or
# closes an issue.
#
# Requires: gh (authenticated), jq
#
# Usage:
#   ./report-status.zsh                                  # markdown to stdout
#   ./report-status.zsh -f table                         # terminal table
#   ./report-status.zsh -o example-org                  # one source org
#   ./report-status.zsh -c                               # only CVE-assigned
#   ./report-status.zsh -s open                          # only open issues
#   ./report-status.zsh -f json | jq '.[] | select(.cve_id)'
#   ./report-status.zsh -O reports/advisory-backlog.md -F

set -euo pipefail

TRACKER="example-org/security-tracking"   # -t overrides; the workflow always passes it
LABEL="advisory"     # tracker label marking an advisory issue; "-" means all
STATE="all"          # all | open | closed  (tracker issue state)
FORMAT="md"          # md | table | json
CVE_ONLY=0
OUTFILE=""           # -O: write the report here instead of stdout
FORCE=0              # -F: allow -O to overwrite an existing file
MD_WIDTH=0           # -w: summary truncation width; 0 = never truncate
typeset -a ORGS
ORGS=()

SCRIPT_NAME=${0:t}   # capture now: inside a zsh function, $0 is the function name

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME [options]

  -t OWNER/REPO  tracker repo to read (default: $TRACKER)
  -o ORG         only advisories whose source repo is in ORG; repeatable
  -l LABEL       tracker label marking an advisory issue (default: $LABEL; "-" = all issues)
  -s STATE       all | open | closed (default: $STATE)
  -f FORMAT      md | table | json (default: $FORMAT)
  -c             only advisories that have a CVE assigned
  -w N           truncate summaries to N chars (0 = never; default: $MD_WIDTH)
  -O FILE        write the report to FILE instead of stdout ("-" means stdout)
  -F             allow -O to overwrite an existing file
  -h             this help
EOF
  exit "${1:-0}"
}

while getopts ":t:o:l:s:f:w:O:cFh" opt; do
  case $opt in
    t) TRACKER=$OPTARG ;;
    o) ORGS+=("$OPTARG") ;;
    l) LABEL=$OPTARG ;;
    s) STATE=$OPTARG ;;
    f) FORMAT=$OPTARG ;;
    w) MD_WIDTH=$OPTARG ;;
    O) OUTFILE=$OPTARG ;;
    c) CVE_ONLY=1 ;;
    F) FORCE=1 ;;
    h) usage 0 ;;
    :) print -u2 "error: -$OPTARG requires an argument"; usage 1 ;;
    \?) print -u2 "error: unknown option -$OPTARG"; usage 1 ;;
  esac
done

[[ $TRACKER == */* ]] || { print -u2 "error: -t wants OWNER/REPO, got: $TRACKER"; usage 1 }
case $STATE in
  all|open|closed) ;;
  *) print -u2 "error: bad -s state: $STATE"; usage 1 ;;
esac
case $FORMAT in
  md|table|json) ;;
  *) print -u2 "error: bad -f format: $FORMAT"; usage 1 ;;
esac
[[ $MD_WIDTH == <-> ]] && (( MD_WIDTH == 0 || MD_WIDTH >= 10 )) || {
  print -u2 "error: -w wants 0 or an integer >= 10"; usage 1 }

# Validate -O up front so we fail before spending any API calls.
if [[ -n $OUTFILE && $OUTFILE != - ]]; then
  if [[ -e $OUTFILE ]] && (( ! FORCE )); then
    print -u2 "error: $OUTFILE exists (pass -F to overwrite)"; exit 1
  fi
  typeset outdir=${OUTFILE:h}
  [[ -d $outdir ]] || { print -u2 "error: no such directory: $outdir"; exit 1 }
  [[ -w $outdir ]] || { print -u2 "error: directory not writable: $outdir"; exit 1 }
fi

command -v gh >/dev/null || { print -u2 "error: gh not found"; exit 127 }
command -v jq >/dev/null || { print -u2 "error: jq not found"; exit 127 }
gh auth status >/dev/null 2>&1 || { print -u2 "error: gh is not authenticated (run: gh auth login)"; exit 1 }

# --- read the tracker issues --------------------------------------------------
# NB: do not name a variable `path` — in zsh that is tied to $PATH.
typeset api_path="/repos/$TRACKER/issues?per_page=100&state=$STATE&sort=created&direction=desc"
[[ $LABEL != - ]] && api_path+="&labels=$LABEL"

print -u2 "→ reading issues from $TRACKER …"
typeset raw
if ! raw=$(gh api --paginate --slurp "$api_path" 2>&1); then
  # gh appends its own "gh: ..." line to the body, so $raw isn't valid JSON — scrape it.
  typeset why
  why=$(print -r -- "$raw" | sed -n 's/.*"message":"\([^"]*\)".*/\1/p' | head -1)
  print -u2 "error: cannot read issues in $TRACKER: ${why:-${raw//$'\n'/ }}"
  print -u2 "hint: the token needs Issues:read on that repo"
  exit 1
fi

# --- normalize ----------------------------------------------------------------
# Everything below the sync's END_MARKER is human-written, so the snapshot is
# parsed only up to that marker: a triage comment that names some *other* GHSA
# (e.g. "variant of GHSA-…") must not be mistaken for this issue's own id.
# Issues with no snapshot at all (manually filed reports) keep their label- and
# title-derived fields and simply carry no GHSA.
typeset all_json
all_json=$(print -r -- "$raw" | jq -c --arg tracker "$TRACKER" '
  (if length > 0 and (.[0]|type) == "array" then add else . end) // []

  # Pull requests come back from the issues endpoint too.
  | map(select(has("pull_request") | not))

  | map(
      (.body // "")                                              as $body
    | ([.labels[]?.name])                                        as $labels
    # capture() emits *nothing* when the regex misses, and `X as $y` over an
    # empty stream drops the whole row — so every binding here ends in `// null`.
    | ((try ($body | capture("<!-- ghsa-sync-meta (?<j>\\{[^}]*\\}) -->") | .j | fromjson)
        catch null) // null)                                     as $meta
    | (if $meta then ($body | split("<!-- /ghsa-sync -->")[0]) else "" end) as $snap

    | (($snap | capture("\\*\\*Source repo:\\*\\* `(?<v>[^`]+)`") | .v) // null)  as $src
    | (($snap | capture("\\*\\*GHSA:\\*\\* \\[(?<id>GHSA-[^\\]]+)\\]\\((?<u>[^)]+)\\)")) // null) as $g
    # For a mirrored issue the CVE field in the snapshot is authoritative. The title
    # is scanned only for directly filed reports, where there is no snapshot —
    # otherwise a summary that merely *names* a CVE ("residual of CVE-…", or an
    # advisory literally titled "CVE-2020-12345") gets it wrongly attributed.
    | (($snap | capture("\\*\\*CVE:\\*\\* (?<v>CVE-[0-9]{4}-[0-9]+)") | .v)
       // (if $meta then null else ((.title // "") | capture("(?<v>CVE-[0-9]{4}-[0-9]+)") | .v) end)
       // null)                                                  as $cve
    | (($snap | capture("\\*\\*Reported severity[^*]*\\*\\* (?<v>[A-Za-z]+)") | .v | ascii_downcase)
       // null)                                                  as $rsev
    # Anchored to the severity line: the Details section quotes the reporter
    # verbatim and often contains a "(CVSS 9.8)" of its own.
    | (($snap | capture("\\*\\*Reported severity[^*]*\\*\\* [A-Za-z]+ \\(CVSS (?<v>[0-9.]+)\\)")
        | .v | tonumber) // null)                                as $cvss
    | (($snap | capture("\\*\\*Published:\\*\\* (?<v>[0-9]{4}-[0-9]{2}-[0-9]{2})") | .v) // null) as $pub
    | (($snap | capture("\\*\\*Reported \\(advisory created\\):\\*\\* (?<v>[0-9]{4}-[0-9]{2}-[0-9]{2})") | .v)
       // ((.created_at // "") | split("T")[0])
       // null)                                                  as $reported

    | ($labels | map(select(startswith("repo:")) | .[5:]) | first)    as $repo_label
    | ($labels | map(select(startswith("type:")) | .[5:]))            as $types
    # sev:* and status:* are single-value axes, so a second label is a triage
    # bug. Join rather than silently picking one — the report should show it.
    | ($labels | map(select(startswith("sev:"))    | .[4:]) | sort | join(" + ")
       | if . == "" then null else . end)                             as $sev
    | ($labels | map(select(startswith("status:")) | .[7:]) | sort | join(" + ")
       | if . == "" then null else . end)                             as $status

    | {
        issue:        .number,
        issue_url:    .html_url,
        issue_state:  .state,
        # "[libparse] Foo" -> "Foo"; manual reports use the same title convention.
        summary:      ((.title // "") | sub("^\\[[^\\]]*\\]\\s*"; "")),
        org:          (if $src then ($src | split("/")[0]) else ($tracker | split("/")[0]) end),
        repo:         (if $src then ($src | split("/")[1]) else $repo_label end),
        source_repo:  $src,
        ghsa_id:      ($g.id // null),
        ghsa_url:     ($g.u // null),
        ghsa_state:   ($meta.state // null),
        cve_id:       $cve,
        # MITRE CVE Program record; the old cve.mitre.org CGI 301s here.
        cve_url:      (if $cve then "https://www.cve.org/CVERecord?id=" + $cve else null end),
        # Assessed by the VMT (label) vs. claimed by the reporter (snapshot).
        # These are deliberately separate: a reported severity is never trusted.
        severity:     $sev,
        reported_severity: $rsev,
        reported_cvss: $cvss,
        status:       $status,
        types:        $types,
        labels:       $labels,
        reported:     $reported,
        published:    $pub,
        updated:      ((.updated_at // "") | split("T")[0]),
        mirrored:     ($meta != null)
      })

  | sort_by(-.issue)')

if (( ${#ORGS} > 0 )); then
  all_json=$(print -r -- "$all_json" \
    | jq -c --argjson orgs "$(printf '%s\n' "${ORGS[@]}" | jq -R . | jq -s -c .)" \
        'map(select(.org as $o | $orgs | index($o)))')
fi
(( CVE_ONLY )) && all_json=$(print -r -- "$all_json" | jq -c 'map(select(.cve_id != null))')

typeset count
count=$(print -r -- "$all_json" | jq 'length')
print -u2 "  $count advisor$( (( count == 1 )) && print -n y || print -n ies)"

# Refuse to clobber a committed report with an empty one: a token that lost its
# Issues:read grant would otherwise quietly wipe reports/ on the next run.
if (( count == 0 )) && [[ -n $OUTFILE && $OUTFILE != - ]]; then
  print -u2 "error: no advisories matched; refusing to write $OUTFILE"
  exit 1
fi

# --- render -------------------------------------------------------------------
# Everything here writes to stdout, so -O can capture the whole report with one
# redirect. Progress and warnings stay on stderr regardless.
render_md() {
  print -r -- "$all_json" | jq -r --argjson w "$MD_WIDTH" --arg tracker "$TRACKER" '
    # escape pipes so a summary containing "|" cannot break the table
    def cell: (. // "–") | tostring | gsub("\\|"; "\\\\|") | gsub("\n"; " ");
    def trunc($n): if $n > 0 and (. | length) > $n then (.[0:$n-1] + "…") else . end;
    def counts(f): (map(f) | group_by(.) | map("\(.[0]) \(length)") | join(", "))
                   | if . == "" then "–" else . end;

    def row:
      "| [#\(.issue)](\(.issue_url)) " +
      "| \(.repo | cell) " +
      "| \(if .ghsa_id then "[`\(.ghsa_id)`](\(.ghsa_url))" else "–" end) " +
      "| \(if .cve_id then "[`\(.cve_id)`](\(.cve_url))" else "–" end) " +
      "| \(if .severity then
              (if (.severity == "critical" or .severity == "high") then "**\(.severity)**" else .severity end)
            elif .reported_severity then "_\(.reported_severity) (unverified)_"
            else "–" end) " +
      "| \(.status | cell) " +
      "| \(.reported | cell) " +
      "| \(.updated | cell) " +
      "| \((.summary | cell) | trunc($w)) |";

    def head:
      "| Issue | Repo | GHSA | CVE | Severity | Status | Reported | Activity | Summary |",
      "| --- | --- | --- | --- | --- | --- | --- | --- | --- |";
    def table: if length > 0 then (head, (.[] | row)) else "_Nothing here._" end;

    # duplicate / wontfix / published are terminal dispositions: nothing is owed
    # on them. They stay in the report as the record, but below the live work.
    # Matched per label so a double-labelled issue ("published + fixed") settles
    # with the terminal one rather than sitting at the top of the backlog.
    def settled: ((.status // "") | split(" + ")
                  | any(. == "duplicate" or . == "wontfix" or . == "published"));

    (map(select(settled | not)))                                   as $live
    # Compound key so issues that share a reported date (a batch of reports
    # filed together) still land newest-issue-first, matching the table above.
  | (map(select(settled)) | sort_by([(.reported // ""), .issue]) | reverse) as $done
  |
    "# Advisory backlog",
    "",
    "One row per issue labelled `advisory` in [`\($tracker)`](https://github.com/\($tracker)/issues).",
    "Generated by `.github/actions/report-status.zsh`; edits here are overwritten.",
    "",
    "**Severity** is the VMT'"'"'s assessed `sev:*` label. Where none is set yet the",
    "reporter'"'"'s own claim is shown as _italic (unverified)_ — it is never trusted as-is.",
    "**Activity** is the issue'"'"'s last update — a stale date on a live row means it has gone quiet.",
    "",
    "## Open advisories",
    "",
    "\($live | length) advisories still owed something — triage, confirmation, a fix or a release.",
    "Newest issue first.",
    "",
    ($live | table),
    "",
    "## Settled",
    "",
    "\($done | length) advisories closed out as `duplicate`, `wontfix` or `published`, kept for the",
    "record. Most recently reported first.",
    "",
    ($done | table),
    "",
    "**Totals** — \(length) advisories, \([.[] | select(.cve_id)] | length) with a CVE, " +
      "\([.[] | select(.ghsa_id)] | length) mirrored from a GHSA, " +
      "\([.[] | select(.ghsa_id | not)] | length) filed directly.",
    "",
    "- by status: \(counts(.status // "unlabelled"))",
    "- by assessed severity: \(counts(.severity // "unassessed"))",
    "- by reported severity: \(counts(.reported_severity // "none"))",
    "- by type: \([.[].types[]] | group_by(.) | map("\(.[0]) \(length)") | join(", ") | if . == "" then "–" else . end)",
    "- by issue state: \(counts(.issue_state))",
    "- CVEs: \([.[] | select(.cve_id) | {id: .cve_id, url: .cve_url}] | unique_by(.id)
               | map("[`\(.id)`](\(.url))") | join(", ") | if . == "" then "–" else . end)"'
}

render_table() {
  print -r -- "$all_json" | jq -r '
    def trunc($n): if (. | length) > $n then (.[0:$n-1] + "…") else . end;
    (["ISSUE","REPO","GHSA","CVE","SEVERITY","STATUS","REPORTED","SUMMARY"]),
    (.[] | [ "#\(.issue)",
             (.repo // "-"),
             (.ghsa_id // "-"),
             (.cve_id // "-"),
             (if .severity then (.severity | ascii_upcase)
              elif .reported_severity then "(\(.reported_severity))"
              else "-" end),
             (.status // "-"),
             (.reported // "-"),
             (.summary | trunc(64)) ])
    | @tsv' | column -t -s $'\t'

  print -r -- "$all_json" | jq -r '
    def counts(f): (map(f) | group_by(.) | map("\(.[0])=\(length)") | join(" "))
                   | if . == "" then "-" else . end;
    "\n── totals ────────────────────────────────────────",
    "advisories       : \(length)",
    "with CVE         : \([.[] | select(.cve_id)] | length)",
    "from a GHSA      : \([.[] | select(.ghsa_id)] | length)",
    "filed directly   : \([.[] | select(.ghsa_id | not)] | length)",
    "by status        : \(counts(.status // "unlabelled"))",
    "assessed severity: \(counts(.severity // "unassessed"))",
    "reported severity: \(counts(.reported_severity // "none"))",
    "CVEs             : \([.[].cve_id | select(.)] | unique | join(", ") | if . == "" then "-" else . end)"' >&2
}

emit_report() {
  case $FORMAT in
    json)  print -r -- "$all_json" | jq '.' ;;
    md)    render_md ;;
    table) render_table ;;
  esac
}

if [[ -n $OUTFILE && $OUTFILE != - ]]; then
  # Build in a sibling temp file and rename, so a failure part-way through can't
  # leave a truncated report where a good one used to be.
  typeset staged="$OUTFILE.partial.$$"
  emit_report > "$staged"
  mv -f -- "$staged" "$OUTFILE"
  print -u2 "→ wrote $FORMAT report to $OUTFILE"
else
  emit_report
fi
