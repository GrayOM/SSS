# SSS Direction Handoff

## Product Direction

SSS is a source-code-driven Browser Console PoC generation assistant for security assessors. It reads frontend/source code, extracts concrete request and DOM evidence, promotes only browser-verifiable targets, and emits short self-contained Browser DevTools Console PoCs.

SSS is not a generic SAST list generator. It should produce fewer, better findings that answer where the code is, what user action reaches it, what request or DOM sink is affected, what PoC to paste, and what evidence to capture.

## Architecture

Pipeline:

source -> source intelligence -> candidate finding -> evidence normalization -> promotion gate -> PoC builder -> browser proof output

Core responsibilities:

- `source_intelligence.py`: routes, pages, UI events, API inventory, storage usage, DOM sources, DOM sinks, validation guard hints, business flows.
- `api_candidate_extractor.py`: concrete API call candidates, method/endpoint/payload keys, source lines, UI handler candidates.
- `console_poc_analysis_service.py`: classification, promotion/demotion, interaction hints, report-ready playbook output.
- `poc_templates.py`: direct helper-free PoCs, runtime/page-derived route and
  payload value resolvers, base URL normalization, payload-style preservation,
  destructive endpoint blocking.

## Promotion Rules

Promote only when source evidence is concrete:

- source path and line range exist
- endpoint/method or DOM source/sink is concrete
- handler or user action is reasonably inferred
- direct PoC exists and is helper-free
- endpoint is not destructive
- source is not vendor/build/minified noise
- Browser Console verification is plausible

Demote to review candidate when endpoint/method/page/action is unresolved, evidence is weak, source is compressed/vendor-like, request is session/init/search/recommendation noise, or runtime observation is required before proof.

## PoC Rules

Promoted API PoCs are source-aware direct `fetch` snippets:

- self-contained
- no `window.SSS_POC`
- no common helper requirement
- no interceptor install
- `credentials: "include"`
- prefer actual runtime/page values from `location.pathname`,
  `URLSearchParams(location.search)`, DOM `data-*` attributes, named or hidden
  inputs, storage/session objects, and app global state
- use `REPLACE_WITH_*` only as a final fallback when source/runtime candidates
  cannot provide the value
- response status/content-type/body preview printed for GET and mutation
  requests
- JSON requests use `Content-Type: application/json` and `JSON.stringify(...)`
- FormData requests use `new FormData()`/`fd.append(...)` and must not set a
  manual JSON content type
- URLSearchParams requests use form-encoded body semantics
- `confirm()` guard for POST/PUT/PATCH
- no DELETE or destructive refund/transfer/withdraw/bulk/remove replay PoC
- route params become runtime-aware variables such as `const orderId = ... ||
  "REPLACE_WITH_ORDER_ID"`, not bare test constants by default

A slightly longer source-aware PoC is preferable to a shorter random replay
template. Do not optimize only for line count if that would discard source
context, payload style, or runtime value derivation.

Review candidates should not look confirmed. Prefer manual verification plans and breakpoint/Network-tab guidance. Optional runtime discovery helper output must remain clearly separated from promoted proof.

When a finding already has a safe source-specific executable PoC, promotion
must preserve that code. Do not overwrite DOM or storage PoCs with generic
fallbacks. Examples:

- `event.data` DOM XSS should keep a `window.postMessage(...)` PoC.
- `location.search` DOM XSS should keep a `history.replaceState(...)` PoC.
- storage auth should keep the detected storage type and key.

Only call `_build_playbook_poc()` as fallback when no safe finding-specific
code exists.

## Testing Commands

Use `python3` in this environment:

```bash
python3 scripts/verify_goal.py
python3 scripts/verify_realistic_output.py
python3 scripts/verify_generalization.py
python3 scripts/verify_browser_runtime_pocs.py
python3 -m pytest tests/ -v
```

If `python` is unavailable, do not treat that as a blocker; use `python3`.

`scripts/verify_realistic_output.py` is the output-shape acceptance check. It builds realistic in-memory frontend fixtures for auction bidding, wallet charge, order payment, Stripe checkout, Iamport prepare/verify, account recovery, login, session/search noise, route params, and destructive endpoints. It validates the final `ReadableAnalysisResult`, not just isolated helper functions.

The realistic verifier must stay green before changing promotion, review-candidate, helper, route-param, or action-inference behavior.

`scripts/verify_browser_runtime_pocs.py` is the runtime-aware PoC shape check.
It runs representative fixtures through the real SSS analysis pipeline and
validates generated promoted `console_code` for runtime resolvers, fallback
guards before mutation fetches, payload-style preservation, GET credentials,
source-specific DOM/storage PoCs, and destructive endpoint suppression. When
the Python Playwright package and a Chromium browser are available, the script
creates controlled fixture pages, mocks `fetch`, evaluates generated Console
PoCs in the page context, checks unresolved fallback blocking, validates
resolved request URL/method/credentials/headers/body, and executes DOM
XSS/storage PoCs. If Playwright is unavailable, the script reports that
limitation and keeps deterministic structural simulation as fallback.

## Generalization Corpus

External public repositories can be shallow-cloned under `.external_corpus/`.
That directory is ignored by git and must not be vendored into SSS.

Corpus commands:

```bash
python3 scripts/build_generalization_corpus.py
python3 scripts/verify_generalization.py
```

`scripts/build_generalization_corpus.py` scans ignored public-source clones and
writes only derived metadata to `docs/generalization_corpus.md` and
`docs/generalization_corpus.json`.

`scripts/verify_generalization.py` runs small derived fixtures through the real
SSS pipeline. It currently covers Angular HttpClient aliases, Angular route
style, HTML form actions, named API wrappers, FormData, URLSearchParams, DOM
XSS, storage/auth branches, destructive endpoints, and session/search/init
noise.

Do not break:

- promoted direct PoCs must stay helper-free
- `common_console_helper` must not appear globally beside direct playbooks
- route params must prefer runtime/page-derived values and keep
  `REPLACE_WITH_*` only as fallback
- base URL variables are stripped only when they look like real base URL
  variables (`API_URL`, `API_BASE_URL`, `REACT_APP_API_URL`, `VITE_API_URL`,
  `*_URL`, `*_BASE`, `*_BASE_URL`)
- route-like variables such as `tenantId`, `orgId`, `userId`, `orderId`, and
  `itemId` must stay editable route params
- `payload_style` must flow from API extraction to PoC generation
- Gemini/helper code sanitization must keep unsafe `window.SSS_POC` or
  destructive code out of promoted playbooks
- destructive refund/delete/transfer/withdraw/bulk/remove endpoints must not
  promote direct replay PoCs
- review candidates must remain manual or clearly observational, never
  confirmed vulnerabilities

## Known Limitations

- Frontend source cannot prove backend authorization or validation; promoted findings are runtime verification candidates, not confirmed vulnerabilities.
- Highly dynamic endpoint builders may still require manual review.
- Optional runtime request discovery still exists for some review candidates, but promoted playbooks should remain short direct PoCs.
- Static heuristics can infer common React/Vue/jQuery/vanilla flows, but unusual UI binding patterns may need richer parsing later.
- Search/recommend/session/init noise can remain in `findings` as raw signals for traceability, but should not flood `review_candidates` or promoted playbooks.
- Angular/component-to-injected-service call graphs are still heuristic; direct
  HttpClient calls and alias-derived endpoints are supported, but complex
  observable chains may need manual review.
- Storage/auth branch playbooks may not have an API endpoint; they are promoted
  only when the browser-verifiable target is storage/navigation/DOM behavior.
- Payload style detection is heuristic for heavily abstracted wrappers; unknown
  payloads with insufficient fields should stay manual rather than being forced
  into JSON.
- URLSearchParams payload extraction supports both `.append(...)` and
  `.set(...)`; do not regress this, because otherwise promoted form-encoded
  verification/code PoCs can silently lose email/code fields.
- Runtime resolver aliases cover common account/payment/workspace fields such
  as `buyer_email`, `phoneNo`, `mobileNo`, `telNo`, `authNo`, `certNo`,
  `tenantId`, `orgId`, `workspaceId`, `projectId`, and `teamId`. File-like
  FormData fields (`file`, `image`, `attachment`, `receipt`, `upload`) should
  resolve from file inputs and stop before fetch if still unresolved.
- Function-only `do*` wrappers without real UI events are deliberately
  conservative review candidates.
