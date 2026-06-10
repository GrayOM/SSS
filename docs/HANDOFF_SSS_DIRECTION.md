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
- `poc_templates.py`: short direct helper-free PoCs, route-param constants, base URL normalization, destructive endpoint blocking.

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

Promoted API PoCs are direct `fetch` snippets:

- self-contained
- no `window.SSS_POC`
- no common helper requirement
- no interceptor install
- `credentials: "include"`
- JSON content type for mutation requests
- `confirm()` guard for POST/PUT/PATCH
- no DELETE or destructive refund/transfer/withdraw/bulk/remove replay PoC
- route params become `REPLACE_WITH_*` constants
- response status/content-type/body preview is printed

Review candidates should not look confirmed. Prefer manual verification plans and breakpoint/Network-tab guidance. Optional runtime discovery helper output must remain clearly separated from promoted proof.

## Testing Commands

Use `python3` in this environment:

```bash
python3 scripts/verify_goal.py
python3 scripts/verify_realistic_output.py
python3 scripts/verify_generalization.py
python3 -m pytest tests/ -v
```

If `python` is unavailable, do not treat that as a blocker; use `python3`.

`scripts/verify_realistic_output.py` is the output-shape acceptance check. It builds realistic in-memory frontend fixtures for auction bidding, wallet charge, order payment, Stripe checkout, Iamport prepare/verify, account recovery, login, session/search noise, route params, and destructive endpoints. It validates the final `ReadableAnalysisResult`, not just isolated helper functions.

The realistic verifier must stay green before changing promotion, review-candidate, helper, route-param, or action-inference behavior.

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
- route params must become `REPLACE_WITH_*` constants
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
