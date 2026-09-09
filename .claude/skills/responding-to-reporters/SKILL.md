---
name: responding-to-reporters
description: Use when drafting any reply to a security reporter — acknowledgement, a VMT assessment verdict, a request for more info, a rejection of a fabricated or out-of-scope report — or when unsure of the tone or what may be promised.
---

# Responding to reporters

You draft a reply for a **human VMT member to review and send** — never send it
yourself unless the operator explicitly delegated that. The response lead (the
on-call VMT member who acknowledged the report) owns the conversation.

**Confidentiality (non-negotiable):** this repo is private and embargo-sensitive.
Never paste report contents, advisory text, reporter identities, or private repo
links into a web search or any external service. Public-info lookups only.

## Rules that hold for every reply

1. **Acknowledge fast.** The OpenSSF guide recommends acknowledging within 1–2
   days (`governance/security/response-process.md`, Intake). Acknowledgement
   carries no assessment — it only says "we are looking at this."
2. **Always thank the reporter — even for slop.** Courtesy is policy
   (response-process.md: "Regardless of the assessment outcome, the response
   should be courteous and thank the reporter"). Today's spammer may file
   tomorrow's real bug. Never snarky, never accusatory, never debate.
3. **Match the channel; don't hardcode it.** Endorsed channels are defined by
   `governance/security/response-process.md` and each repo's `SECURITY.md` —
   read them, don't assume. As of writing: an email report is answered by
   replying to the reporter **cc'ing security@example.org**; a GitHub Security
   Advisory is answered with a **comment on the advisory** (it arrives in
   "Triage" state). Check whether the current policy still advertises email
   before citing it.
4. **Confirmed vulnerability → offer involvement.** If a patch will be made,
   offer the reporter the chance to review/contribute (response-process.md,
   "Responding to the reporter"). As project good practice, also ask their
   preference on credit and any embargo/disclosure-timing constraints — these
   are not required by response-process.md.
5. **Don't apologize, and don't dwell on delay.** Even when a reply is badly
   overdue, state the assessment and move on; drafts that open by apologizing for
   the wait get cut. What a waiting reporter actually values is substance — "your
   report was the earliest we received on this" does more than any apology.

**Disclosure timing is the project's to set, not the reporter's to grant.**
Asking "do you have timing constraints?" opens a negotiation. Reporters may
impose deadlines (some research teams use 90 or 120 days; some distribution
lists cap embargoes at 14 days) and the VMT negotiates against those — but with
several independent reporters, multiparty-disclosure guidance is to drive one
timeline rather than reconcile many. Prefer *telling* a reporter the expected
timing over *asking* for theirs; reporters generally honour embargoes they were
kept inside of.

**Duplicate reporters get less, deliberately.** Where a report duplicates a
finding already under assessment, the offer to contribute to the fix can
reasonably be dropped: the process conditions it on "if a patch is to be made"
for *that* report, and widening the embargo circle to a second reporter exposes
another party's material. Credit is the exception — it costs nothing and divides
infinitely, so credit independent rediscovery even when nothing else is offered.

## The "please share a runnable PoC" filter

When a report references real code but its mechanism is unproven, or when it
reads as mixed (real symbols, incoherent flow), do **not** dismiss it. Reply
asking for a **minimal runnable proof-of-concept**. This is the standard cheap
filter: genuine reporters produce one; spammers vanish. Non-reproduction is not
refutation — see REQUIRED SUB-SKILL: reproducing-security-reports.

## Never promise / never include

| Never PROMISE | Never INCLUDE |
|---|---|
| A fix timeline or release date | Links to this private repo or the advisory draft |
| That a CVE will be assigned | Any other report's contents |
| A bug bounty (the project has none) | Team-internal discussion or reviewer names |
| Embargo terms the VMT has not agreed | Reproduction details for an unrelated issue |
| — | The agent-attribution footer — this is a human-sent reply, not agent-posted content (that footer is for tracker comments; see **operating-the-tracker**) |

## Fabricated report — the one to get right

Factual, brief, non-accusatory. State the verifiable fact and close in one round.
**Never mention AI or LLMs. Never imply bad faith.** Example:

> Thank you for your report. We reviewed the referenced code paths: the functions
> `lp_frame_unpack_ext` and `lp_secure_realloc` do not exist in libparse, and
> `src/frame/decode_fast.c` is not a path in the repository. We are therefore
> unable to act on this report. If you have a runnable proof-of-concept against a
> current release, we would be glad to look again.

Say what you checked (specific symbols/paths that failed to exist). Don't
speculate about how the report was produced.

## Templates per assessment outcome

One concise template for each VMT outcome — acknowledgement, request-for-PoC,
vulnerability-confirmed, working-as-intended / bug / feature-request,
out-of-threat-model, out-of-scope-upstream, fabricated — lives in
**reply-templates.md** (same directory). Pick the one matching the verdict and
adapt it; keep the five universal rules above.

See also: triaging-security-reports (produces the verdict you are replying to),
detecting-report-slop (fabricated vs. mixed vs. credible), threat-model-and-scope
(in/out of scope and upstream), assessing-severity, operating-the-tracker (labels).
