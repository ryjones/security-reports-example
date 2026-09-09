# [parse-playground] Authentication bypass in the hosted frame upload demo

## Summary

Hello,

I am reporting a vulnerability in the **parse-playground** web demo (`example-org/parse-playground`, `main` branch). The browser demo lets a visitor upload a frame which the backend forwards to a hosted parse-server. The upload handler accepts a `key_id` form field and uses it to select the verification key server-side without checking that the visitor is allowed to use that key. In my testing, supplying another tenant's `key_id` causes the demo to verify — and display as authentic — a frame I signed under *my* key, effectively an authentication bypass of the demo's tenant isolation.

I built the demo from `main` (which vendors libparse 2.4.1) and reproduced against a local instance. The upstream libparse library is not at fault: `lp_frame_verify` correctly rejects the frame under the *right* key. This is specific to the playground's key-selection logic.

## Affected component

- Repository: `example-org/parse-playground`
- Component: upload handler (`web/upload.js`, `selectKey()` / `handleUpload()`) calling into the `libparse-python` binding via `api/verify.py`
- Version: latest `main`

## Details

`handleUpload()` reads `req.body.key_id`, passes it to `selectKey()`, which loads `keys/<key_id>.bin` from disk with no ownership check, and then calls the verify endpoint. Because the tenant is derived from the session but the key from the request, the two can be mixed. The fix is to derive `key_id` from the session, or to check ownership before loading.

I have a patch and a reproducer.

## Requested action

Please assign a CVE and coordinate a fix release of parse-playground.

Thanks,
M. Contributor

---

## GROUND TRUTH (do not show to triage agents)

**Verdict: OUT OF SCOPE — unsupported project. Disposition: best-effort only; polite redirect. Not tracked as a supported-project security advisory; do NOT assign a CVE through the libparse/parse-server advisory process on the basis of the playground alone.**

The report targets **parse-playground**, which the security response process explicitly lists as **without security support**. Per the governance response-process scope section:

> This document applies in full to vulnerabilities found in libparse [plus, in lock-step, parse-server and the bindings libparse-python / libparse-go].
>
> Other repositories are not considered to have security support, although vulnerabilities may still be addressed on a best-effort basis. [parse-playground and parse-cli are specifically named as lacking security support.]

Correct triage:
- Recognize the affected component is parse-playground, NOT libparse, parse-server, or a supported binding.
- Do NOT run the full advisory workflow (CVE request, severity assignment, board tracking) as if it were an in-scope libparse bug.
- Respond politely: thank the reporter, explain parse-playground is a demonstration repo without security support and receives only best-effort fixes; point them to the response-process scope and offer to forward or open a public issue on the playground repo.
- IMPORTANT nuance: if the described flaw could be traced to a genuine defect in **libparse itself** (or `libparse-python`, a supported binding), that portion WOULD be in scope. But as written the alleged bug is in the playground's own key-selection glue (`web/upload.js`), not in a libparse API — the reporter even says `lp_frame_verify` behaves correctly — so it is out of scope as reported. A triager who reflexively opens a libparse advisory + CVE for this has mis-scoped it; a triager who simply ignores/deletes it without the polite best-effort redirect has also handled it poorly.

Verification: `../governance/security/response-process.md` scope section — supported set is libparse + parse-server + the bindings; parse-playground explicitly lacks security support (best-effort only). libparse `SECURITY.md` also links to this response process and the README support-limitations disclaimer. `sources.yml` in this tracker lists only libparse and parse-server.
