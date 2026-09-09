#!/usr/bin/env python3
"""Mirror GitHub repository security advisories into tracker issues.

One-way sync: source repos -> this tracker repo. Never writes back to a GHSA.

Design rule: automation writes only objective facts. It owns the snapshot
region of the issue body (between the markers) and, on creation, the repo:*
labels plus the initial status:triage. After creation it NEVER changes
sev:* / status:* / type:* labels or the human discussion below the snapshot —
humans own every status transition. Reported severity/CVSS from the GHSA are
shown as text labelled "unverified" and are never mapped onto our severity
labels.

Requires only the Python standard library. Configured via env vars:

  GITHUB_TOKEN        PAT with:
                        - read on source repos' security advisories
                        - read/write on this repo's issues
  GITHUB_REPOSITORY   tracker repo, "owner/name" (set by Actions)
  SOURCES_FILE        path to sources.yml (default: sources.yml)
  DRY_RUN             if "1"/"true", log actions without writing
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
GRAPHQL = f"{API}/graphql"

# Snapshot region markers. Everything from the start of the body through
# END_MARKER is machine-owned and overwritten on each sync. Everything after
# is human-owned and never touched.
META_RE = re.compile(r"<!-- ghsa-sync-meta (?P<json>\{.*?\}) -->", re.DOTALL)
END_MARKER = "<!-- /ghsa-sync -->"

DRY_RUN = os.environ.get("DRY_RUN", "").lower() in ("1", "true", "yes")


# --------------------------------------------------------------------------
# Minimal HTTP helpers (stdlib only)
# --------------------------------------------------------------------------
def _request(method, url, token, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "security-tracking-sync")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read() or "null")
        except urllib.error.HTTPError as e:
            # Back off on secondary-rate-limit / abuse responses.
            if e.code in (403, 429) and attempt < 3:
                time.sleep(2 ** attempt * 5)
                continue
            sys.stderr.write(f"HTTP {e.code} {method} {url}\n{e.read().decode()}\n")
            raise
    raise RuntimeError("unreachable")


def get_paginated(path, token):
    """GET every page of a list endpoint, following Link headers."""
    url = f"{API}{path}"
    if "?" not in url:
        url += "?per_page=100"
    elif "per_page" not in url:
        url += "&per_page=100"
    out = []
    while url:
        _, headers, page = _request("GET", url, token)
        if isinstance(page, list):
            out.extend(page)
        url = _next_link(headers.get("Link", ""))
    return out


def _next_link(link_header):
    for part in link_header.split(","):
        m = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def graphql(token, query, variables):
    _, _, body = _request("POST", GRAPHQL, token, {"query": query, "variables": variables})
    if body and body.get("errors"):
        raise RuntimeError(json.dumps(body["errors"]))
    return (body or {}).get("data") or {}


# --------------------------------------------------------------------------
# sources.yml (tiny hand-rolled parser; avoids a PyYAML dependency)
# --------------------------------------------------------------------------
def load_sources(path):
    sources = []
    current = None
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            stripped = line.strip()
            if stripped.startswith("- "):
                if current:
                    sources.append(current)
                current = {}
                stripped = stripped[2:].strip()
                if not stripped:
                    continue
            if current is not None and ":" in stripped:
                key, _, val = stripped.partition(":")
                current[key.strip()] = val.strip().strip('"').strip("'")
    if current:
        sources.append(current)
    return [s for s in sources if s.get("repo")]


# --------------------------------------------------------------------------
# Snapshot rendering
# --------------------------------------------------------------------------
def reported_date(adv):
    """The advisory's report date (YYYY-MM-DD) for the board 'Reported date'
    field and the backlog-age view. Uses GHSA creation, falling back to
    publication. Returns None if neither is present."""
    ts = adv.get("created_at") or adv.get("published_at")
    return ts[:10] if ts else None


def render_snapshot(adv, source):
    ghsa = adv.get("ghsa_id", "")
    cve = adv.get("cve_id") or "—"
    state = adv.get("state", "unknown")
    sev = adv.get("severity") or "unset"
    cvss = (adv.get("cvss") or {}).get("score")
    cvss_str = f" (CVSS {cvss})" if cvss else ""
    summary = (adv.get("summary") or "").strip()
    description = (adv.get("description") or "").strip()
    html_url = adv.get("html_url", "")

    credits = adv.get("credits") or []
    reporters = ", ".join(
        f"@{c['user']['login']}" for c in credits if c.get("user", {}).get("login")
    ) or "—"

    vulns = adv.get("vulnerabilities") or []
    if vulns:
        rows = ["| Package | Affected | Patched |", "|---|---|---|"]
        for v in vulns:
            pkg = (v.get("package") or {}).get("name") or "—"
            rng = v.get("vulnerable_version_range") or "—"
            # patched_versions is a string (e.g. "0.16.0"), not a list.
            patched = v.get("patched_versions") or "—"
            rows.append(f"| {pkg} | {rng} | {patched} |")
        affected = "\n".join(rows)
    else:
        affected = "_None listed._"

    withdrawn = adv.get("withdrawn_at")
    withdrawn_note = (
        f"\n> ⚠️ **Withdrawn upstream** at {withdrawn}.\n" if withdrawn else ""
    )

    meta = json.dumps(
        {"ghsa": ghsa, "state": state, "updated_at": adv.get("updated_at")},
        separators=(",", ":"),
    )

    return f"""<!-- ghsa-sync-meta {meta} -->
> ⚠️ **Auto-synced from the upstream advisory. Do not edit this region** —
> changes here are overwritten on the next sync. Add notes below the line.
{withdrawn_note}
**Source repo:** `{source['repo']}`
**GHSA:** [{ghsa}]({html_url})
**CVE:** {cve}
**GHSA state:** `{state}`
**Reported severity (UNVERIFIED — assess independently):** {sev}{cvss_str}
**Reported by:** {reporters}
**Reported (advisory created):** {(adv.get("created_at") or "—")[:10]}
**Published:** {(adv.get("published_at") or "—")[:10]}

### Summary
{summary or "_No summary._"}

### Details
{description or "_No description._"}

### Affected products (as reported)
{affected}
{END_MARKER}

---
<!-- Everything below is human-owned: triage, discussion, decisions.
     The sync never edits below the marker above. -->

### Triage
- [ ] Confirmed
- [ ] Assessed severity set (apply a `sev:*` label)
- [ ] Status advanced beyond `status:triage`
- [ ] CVE requested / assigned

_Notes:_
"""


def split_body(body):
    """Return (human_tail) — the part of an existing body after END_MARKER."""
    idx = body.find(END_MARKER)
    if idx == -1:
        return None
    return body[idx + len(END_MARKER):]


def parse_meta(body):
    m = META_RE.search(body or "")
    if not m:
        return None
    try:
        return json.loads(m.group("json"))
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
# Project (v2) board: write objective fields (Reported date, Source repo) via
# GraphQL.
#
# Only objective facts go on the board automatically; severity/status/etc.
# remain human-filled. Requires the token to also carry org Projects: write.
# All of this is guarded — any failure logs and leaves issue sync untouched.
# --------------------------------------------------------------------------
_Q_PROJECT = """
query($owner:String!, $number:Int!) {
  organization(login:$owner) {
    projectV2(number:$number) {
      id
      fields(first:50) {
        nodes {
          ... on ProjectV2FieldCommon { id name }
          ... on ProjectV2SingleSelectField { id name options { id name } }
        }
      }
    }
  }
}
"""

_M_ADD_ITEM = """
mutation($project:ID!, $content:ID!) {
  addProjectV2ItemById(input:{projectId:$project, contentId:$content}) {
    item { id }
  }
}
"""

_M_SET_DATE = """
mutation($project:ID!, $item:ID!, $field:ID!, $date:Date!) {
  updateProjectV2ItemFieldValue(input:{
    projectId:$project, itemId:$item, fieldId:$field, value:{date:$date}
  }) { projectV2Item { id } }
}
"""

_M_SET_SELECT = """
mutation($project:ID!, $item:ID!, $field:ID!, $opt:String!) {
  updateProjectV2ItemFieldValue(input:{
    projectId:$project, itemId:$item, fieldId:$field,
    value:{singleSelectOptionId:$opt}
  }) { projectV2Item { id } }
}
"""


def resolve_project(token, owner, number, date_field, source_field):
    """Resolve the project and the fields we write. Returns a config dict
    {project_id, date_field_id, source_field_id, source_options} where any
    missing field is None/{}; or None if the project itself isn't found."""
    data = graphql(token, _Q_PROJECT, {"owner": owner, "number": number})
    proj = ((data.get("organization") or {}).get("projectV2")) or None
    if not proj:
        return None
    cfg = {"project_id": proj["id"], "date_field_id": None,
           "source_field_id": None, "source_options": {}}
    for node in (proj.get("fields") or {}).get("nodes") or []:
        name = node.get("name")
        if name == date_field:
            cfg["date_field_id"] = node.get("id")
        elif name == source_field:
            cfg["source_field_id"] = node.get("id")
            cfg["source_options"] = {o["name"]: o["id"] for o in node.get("options") or []}
    return cfg


def ensure_item(token, project_id, content_node_id):
    """Add the issue to the project and return its item id. Idempotent —
    returns the existing item if Auto-add already added it."""
    data = graphql(token, _M_ADD_ITEM, {"project": project_id, "content": content_node_id})
    return data["addProjectV2ItemById"]["item"]["id"]


def set_board_fields(token, cfg, content_node_id, date, source_option_name):
    """Write the objective board fields for one issue."""
    item_id = ensure_item(token, cfg["project_id"], content_node_id)
    if cfg["date_field_id"] and date:
        graphql(token, _M_SET_DATE, {
            "project": cfg["project_id"], "item": item_id,
            "field": cfg["date_field_id"], "date": date})
    opt_id = cfg["source_options"].get(source_option_name)
    if cfg["source_field_id"] and opt_id:
        graphql(token, _M_SET_SELECT, {
            "project": cfg["project_id"], "item": item_id,
            "field": cfg["source_field_id"], "opt": opt_id})


# --------------------------------------------------------------------------
# Tracker issue operations
# --------------------------------------------------------------------------
def load_tracker_index(tracker, token):
    """Map ghsa_id -> issue for existing mirror issues (label 'advisory')."""
    issues = get_paginated(
        f"/repos/{tracker}/issues?state=all&labels=advisory", token
    )
    index = {}
    for issue in issues:
        if "pull_request" in issue:
            continue
        meta = parse_meta(issue.get("body", ""))
        if meta and meta.get("ghsa"):
            index[meta["ghsa"]] = issue
    return index


def create_issue(tracker, token, adv, source):
    title = f"[{source.get('tag', source['repo'])}] {adv.get('summary') or adv['ghsa_id']}"
    labels = ["advisory", "status:triage", source["label"]]
    if adv.get("withdrawn_at"):
        labels.append("withdrawn")
    payload = {
        "title": title[:250],
        "body": render_snapshot(adv, source),
        "labels": labels,
    }
    if DRY_RUN:
        print(f"  [dry-run] CREATE issue: {title}")
        return None
    _, _, issue = _request("POST", f"{API}/repos/{tracker}/issues", token, payload)
    print(f"  created #{issue['number']}: {title}")
    return issue


def update_issue(tracker, token, issue, adv, source):
    old_meta = parse_meta(issue.get("body", "")) or {}
    tail = split_body(issue.get("body", "")) or ""
    new_body = render_snapshot(adv, source) + tail

    content_changed = old_meta.get("updated_at") != adv.get("updated_at")
    state_changed = old_meta.get("state") != adv.get("state")
    num = issue["number"]

    if not content_changed and not state_changed:
        return  # nothing to do

    if DRY_RUN:
        print(f"  [dry-run] UPDATE #{num} (state_changed={state_changed})")
        return

    _request(
        "PATCH", f"{API}/repos/{tracker}/issues/{num}", token, {"body": new_body}
    )

    notes = []
    if state_changed:
        notes.append(
            f"GHSA state changed: `{old_meta.get('state')}` → `{adv.get('state')}`."
        )
    if adv.get("withdrawn_at") and "withdrawn" not in [
        l["name"] for l in issue.get("labels", [])
    ]:
        notes.append("Advisory was **withdrawn upstream**.")
        _request(
            "POST",
            f"{API}/repos/{tracker}/issues/{num}/labels",
            token,
            {"labels": ["withdrawn"]},
        )
    elif content_changed:
        notes.append("Upstream advisory updated; snapshot refreshed.")

    if notes:
        _request(
            "POST",
            f"{API}/repos/{tracker}/issues/{num}/comments",
            token,
            {"body": "🔄 " + " ".join(notes)},
        )
    print(f"  updated #{num} (state_changed={state_changed})")


# --------------------------------------------------------------------------
def main():
    token = os.environ.get("GITHUB_TOKEN")
    tracker = os.environ.get("GITHUB_REPOSITORY")
    sources_file = os.environ.get("SOURCES_FILE", "sources.yml")
    if not token or not tracker:
        sys.exit("GITHUB_TOKEN and GITHUB_REPOSITORY must be set.")

    sources = load_sources(sources_file)
    print(f"Tracker: {tracker} | sources: {[s['repo'] for s in sources]}"
          + (" | DRY RUN" if DRY_RUN else ""))

    index = load_tracker_index(tracker, token)
    print(f"Existing mirror issues: {len(index)}")

    # Optional board sync. Skipped entirely (with a log line) unless a project
    # number is configured and the project resolves. Any failure here never
    # affects issue mirroring.
    board = None
    proj_number = os.environ.get("PROJECT_NUMBER")
    proj_owner = os.environ.get("PROJECT_OWNER") or tracker.split("/")[0]
    date_field = os.environ.get("REPORTED_DATE_FIELD", "Reported date")
    source_field = os.environ.get("SOURCE_REPO_FIELD", "Source repo")
    if proj_number and not DRY_RUN:
        try:
            board = resolve_project(
                token, proj_owner, int(proj_number), date_field, source_field
            )
            if not board:
                print(f"Board sync: project #{proj_number} not found; skipping.")
            else:
                wrote = [n for n, k in (
                    (date_field, "date_field_id"), (source_field, "source_field_id")
                ) if board.get(k)]
                if wrote:
                    print(f"Board sync: writing {wrote} to project #{proj_number}.")
                else:
                    print(f"Board sync: no writable fields found; skipping.")
                    board = None
        except Exception as e:  # noqa: BLE001 — never let the board break issue sync
            print(f"Board sync: resolution failed; skipping. ({e})")
            board = None

    def sync_board(issue, adv, source):
        if not board or not issue:
            return
        node_id = issue.get("node_id")
        if not node_id:
            return
        try:
            set_board_fields(token, board, node_id, reported_date(adv),
                             source.get("tag", source["repo"]))
        except Exception as e:  # noqa: BLE001
            print(f"    board sync failed for #{issue.get('number')}: {e}")

    for source in sources:
        print(f"\n== {source['repo']} ==")
        advisories = get_paginated(
            f"/repos/{source['repo']}/security-advisories", token
        )
        print(f"  {len(advisories)} advisories")
        for adv in advisories:
            ghsa = adv.get("ghsa_id")
            if not ghsa:
                continue
            if ghsa in index:
                issue = index[ghsa]
                update_issue(tracker, token, issue, adv, source)
            else:
                issue = create_issue(tracker, token, adv, source)
            sync_board(issue, adv, source)


if __name__ == "__main__":
    main()
