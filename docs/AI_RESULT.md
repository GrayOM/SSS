# AI Implementation Result

## poc_templates.py fix (this session)

### What was wrong

`app/services/poc_templates.py` existed but had two values that did not match
the specification:

| Constant | Was | Required |
|---|---|---|
| `MAX_POC_LINES` | `10` | `12` |
| `INTERCEPTOR_SIGS[-1]` | `'TARGET_ENDPOINT'` | `'TARGET_ENDPOINT ='` |

### What changed

`app/services/poc_templates.py` — two one-line edits:
- `MAX_POC_LINES = 10` -> `MAX_POC_LINES = 12`
- `'TARGET_ENDPOINT'` -> `'TARGET_ENDPOINT ='` in `INTERCEPTOR_SIGS`

No other file was modified.

### pytest result

```
373 passed in 2.97s
```

All tests green, including security (ZIP Slip, symlink, size, extension allowlist),
ASCII/mojibake, and every `test_poc_templates_*` test.

### Tests that could NOT be passed

None. Every test passes without weakening any test or security control.

---

## Prior session summary

The SSS engine has been redesigned from a regex request-scraper + 200-line
interceptor into a proof-quality analyzer that emits short, self-contained PoCs.

### New analysis -> PoC flow

```
ZIP upload
  -> static source-to-sink analysis (regex patterns in mock; LLM in gemini)
  -> poc_templates builder selection per vuln class
  -> short direct PoC (1-10 lines, self-contained)
  -> promotion gated on PROOF QUALITY (short PoC + no hook installer)
  -> demoted findings -> manual_plan or fallback discovery interceptor
```

## Changed Files

| File | Type | Description |
|---|---|---|
| `app/services/poc_templates.py` | NEW | Three typed PoC builders; `is_interceptor_free()` guard |
| `app/services/console_poc_analysis_service.py` | MODIFIED | Import templates; update `_mk_dom_xss`, `_mk_auth_bypass`, `_mk_validation_bypass`; add `_build_playbook_poc`; fix promotion logic |
| `app/services/prompt_builder.py` | MODIFIED | Add source/sink chain requirement to LLM prompt |
| `tests/test_console_poc_analysis_service.py` | MODIFIED | Update 10 anti-pattern tests; add 16 proof-quality + template tests |
| `tests/test_prompt_builder.py` | MODIFIED | Update 1 test for new prompt content |
| `docs/AI_REVIEW.md` | NEW | Anti-pattern map |

## Before / After PoC Length Comparison

### DOM XSS

```
BEFORE (interceptor): 60 lines (SSS_REVIEW_POC_STATE, TARGET_ENDPOINT, window.fetch hook)
AFTER (template):     1 line
  location.hash = '<img src=x onerror=console.log(1)>'; location.reload();
```

### Client-side Auth Bypass (storage pattern)

```
BEFORE (interceptor): 60 lines (fetch hook observer)
AFTER (template):     1 line
  sessionStorage.setItem("user", JSON.stringify({"userType": "ADMIN"})); location.reload();
```

### Payment / Parameter Mutation

```
BEFORE (interceptor): 60 lines (global fetch+XHR+axios monkey-patch, capture, replay API)
AFTER (template):     10 lines (self-contained CONFIRM-guarded direct fetch)
  (async () => {
    const CONFIRM_AUTHORIZED_TEST = false;
    if (!CONFIRM_AUTHORIZED_TEST) { console.warn('[SSS PoC] Set CONFIRM_AUTHORIZED_TEST=true to run'); return; }
    const r = await fetch("/api/orders/pay", {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "amount": 1 }),
    });
    console.log('[SSS PoC]', r.status, await r.text().catch(() => ''));
  })();
```

## Promotion Logic Change

Old: demote if `page_hint == generic` OR `action_hint == generic` OR `function_name is None`.
New: short direct PoC (no hook installer, <=10 lines) from a confirmed finding type
(DOM XSS, Client-side Authorization Bypass) bypasses cosmetic hint gates.

```python
is_confirmed_short_poc = has_short_direct_poc and f.vulnerability_type in {
    'DOM XSS', 'Client-side Authorization Bypass',
}
should_review = not is_confirmed_short_poc and (...existing conditions...)
```

## Storage Key Detection

`_mk_auth_bypass` now detects the actual `getItem` key:
- `getItem('user')` / `getItem('userInfo')` -> JSON-object pattern -> `setItem('user', JSON.stringify({userType:'ADMIN'}))`
- `getItem('userType')` / `getItem('role')` -> plain-string pattern -> `setItem('userType', 'ADMIN')`
- Unknown key -> no PoC generated (stays manual_plan)

## How to Run

```bash
python3 -m compileall app tests   # compile check
python3 -m pytest tests/ -q       # 373 tests
```

## Security Review

| Control | Status |
|---|---|
| ZIP Slip / symlink / size / extension allowlist | UNCHANGED |
| Raw file content stripped before API response | UNCHANGED |
| Destructive-endpoint PoC block (refund/transfer/bulk/delete) | UNCHANGED - `_is_safe_endpoint()` in poc_templates |
| `_is_allowed_guarded_poc_code` safety filter | UNCHANGED - CONFIRM-guarded replay passes it |
| ASCII-only PoC output | MAINTAINED - all template outputs are pure ASCII |
| Interceptor (SSS_POC/SSS_REVIEW_POC) | DEMOTED to fallback only; never in promoted findings |

## Remaining Gaps (LLM backend required)

1. **Deep multi-file flows**: mock analyzer detects source/sink within a single
   file. Cross-file flows (e.g. shared utility reads storage, imported function
   reaches sink) require the Gemini backend.

2. **React state -> DOM flow**: `useState` + conditional render reaching
   `dangerouslySetInnerHTML` cannot be traced by regex.

3. **Dynamic endpoint resolution**: `buildApiUrl(action)` and similar runtime
   constructors produce UNKNOWN endpoints. LLM with the full manifest can
   sometimes resolve these.

4. **Auth chain validation**: whether `requireAuth()` actually enforces
   server-side session validation cannot be determined from the frontend alone.
   LLM with backend source context would help.

5. **PoC value inference**: `build_request_replay_poc` uses heuristic test
   values (`amount: 1`, `status: 'TEST_VALUE'`). The LLM backend can emit
   domain-specific values from the finding context.

---

## 2026-06-04 Goal Verification: Base URL Promotion and Self-Contained PoCs

### Final verify_goal.py output

Command used in this environment: `python(){ python3 "$@"; }; python scripts/verify_goal.py`
(`python` is not installed on PATH here; the shell-local shim invokes `/usr/bin/python3`.)

```text
verify_goal: 23 passed, 0 failed
```

Key checks passed:
- `{API_BASE_URL}/login` promoted with `fetch("/login"`.
- `/api/auction/{item.id}/bid` promoted with `const TEST_ID = "REPLACE_WITH_TEST_ID";` and `fetch(`/api/auction/${TEST_ID}/bid`.
- Promoted PoCs contain no `window.SSS_POC`, `window.SSS_REVIEW_POC`, fetch/XHR interceptors, or helper capture signatures.
- `common_console_helper` is `None` when promoted PoCs are self-contained.
- `{API_BASE_URL}/admin/refund` and `DELETE` endpoints do not promote.

### Final pytest summary

Command used in this environment: `python(){ python3 "$@"; }; python -m pytest tests/ -v`

```text
377 passed in 4.59s
```

### Files changed

- `app/services/poc_templates.py`
- `app/services/api_candidate_extractor.py`
- `app/services/console_poc_analysis_service.py`
- `app/services/upload_service.py`
- `app/api/routes_analysis_runs.py`
- `scripts/verify_goal.py`
- `tests/conftest.py`
- `tests/test_api_candidate_extractor.py`
- `tests/test_console_poc_analysis_service.py`
- `docs/AI_RESULT.md`

### Key functions changed

- `normalize_endpoint`: strips leading base URL placeholders/variables such as `{API_BASE_URL}`, `${apiBase}`, and `API_BASE_URL +`.
- `build_request_replay_poc`: emits short, self-contained, CONFIRM-guarded `fetch` PoCs and blocks destructive/unknown endpoints.
- `extract_api_call_candidates`: normalizes base-URL-only paths during inventory extraction and recognizes `axios.create(...).post(...)`.
- `analyze_console_exploitability`: promotes concrete normalized endpoints with helper-free playbook code and hides `common_console_helper` when not needed.
- `prepare_uploaded_zip`: preserves existing upload guards while avoiding the Starlette async read hang seen in this sandbox.

### Revived promoted findings

- `POST {API_BASE_URL}/login` -> promoted as `/login`.
- `POST ${API_BASE_URL}/admin/add-numbers` -> promoted as `/admin/add-numbers`.
- `POST API_BASE_URL + "/generate-lotto"` -> promoted as `/generate-lotto`.
- `axios.create({ baseURL: API_BASE_URL }).post("/login")` -> promoted as `/login`.
- `POST /api/auction/{item.id}/bid` -> promoted with tester-controlled `TEST_ID`.

### Example self-contained console PoCs

```javascript
(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { console.warn('[SSS PoC] Set CONFIRM_AUTHORIZED_TEST=true to run'); return; }
  const r = await fetch("/login", {
    method: "POST", credentials: "include",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  console.log('[SSS PoC]', r.status, await r.text().catch(() => ''));
})();
```

```javascript
(async () => {
  const CONFIRM_AUTHORIZED_TEST = false;
  if (!CONFIRM_AUTHORIZED_TEST) { console.warn('[SSS PoC] Set CONFIRM_AUTHORIZED_TEST=true to run'); return; }
  const TEST_ID = "REPLACE_WITH_TEST_ID";
  const r = await fetch(`/api/auction/${TEST_ID}/bid`, {
    method: "POST", credentials: "include",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ "amount": 1 }),
  });
  console.log('[SSS PoC]', r.status, await r.text().catch(() => ''));
})();
```

### Security review points

- Destructive keywords/methods remain blocked: `refund`, `transfer`, `withdraw`, `bulk`, `delete`, `DELETE`.
- `{API_BASE_URL}/{UNKNOWN_PATH}` remains manual-only.
- Promoted PoCs are helper-free and do not use `window.SSS_POC.find`.
- ZIP Slip, path traversal, upload size, signature, content type, and extraction guards were not weakened.
- No unmet goals remain.

---

## 2026-06-04 Follow-up: Console UX, Proof Steps, and Payload Fidelity

### Final verify_goal.py output

Command used in this environment: `python(){ python3 "$@"; }; python scripts/verify_goal.py`
(`python` is not installed on PATH here; the shell-local shim invokes `/usr/bin/python3`.)

```text
verify_goal: 23 passed, 0 failed
```

### Final pytest summary

Command used in this environment: `python(){ python3 "$@"; }; python -m pytest tests/ -v`

```text
383 passed in 2.93s
```

### Files changed

- `app/services/poc_templates.py`
- `app/services/console_poc_analysis_service.py`
- `app/services/prompt_builder.py`
- `tests/test_console_poc_analysis_service.py`
- `docs/AI_RESULT.md`

### Key functions changed

- `_is_allowed_guarded_poc_code`: allows strict direct `fetch` POST/PUT/PATCH PoCs guarded by browser `confirm()`, while still rejecting `DELETE`, `refund`, `transfer`, `withdraw`, `bulk`, and `delete`.
- `build_request_replay_poc`: uses one-paste browser confirmation, prints status/content-type/body preview, and includes all extracted safe payload keys.
- `_proof_steps`: direct API playbooks now describe paste, approve confirmation, observe response, and compare in Network tab; no helper flow wording remains.
- `analyze_console_exploitability`: promoted findings now get the same short `verification_playbook.console_code` as `result.verification_playbooks`.

### Example generated direct PoC

```javascript
(async () => {
  if (!confirm("[SSS PoC] Run approved POST /api/payments/iamport/complete?")) return;
  const TEST_PAYMENT_UID = "REPLACE_WITH_TEST_PAYMENT_UID";
  const TEST_ORDER_ID = "REPLACE_WITH_TEST_ORDER_ID";
  const TEST_PRODUCT_ID = "REPLACE_WITH_TEST_PRODUCT_ID";
  const r = await fetch("/api/payments/iamport/complete", {
    method: "POST", credentials: "include",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ "merchant_uid": TEST_PAYMENT_UID, "imp_uid": TEST_PAYMENT_UID, "orderId": TEST_ORDER_ID, "productId": TEST_PRODUCT_ID, "amount": 1, "buyer_email": "TEST_VALUE" }),
  });
  console.log('[SSS PoC]', r.status, r.headers.get('content-type'), (await r.text()).slice(0, 500));
})();
```

### Security review points

- Destructive endpoint blocking remains before guard acceptance.
- Promoted PoCs remain helper-free and within the 12 non-empty line limit.
- Promoted proof steps do not mention `window.SSS_POC`, `armMutation`, `list()`, or `common_console_helper`.
- Promoted finding-level playbook code no longer exposes `SSS_REVIEW_POC_STATE`, `TARGET_ENDPOINT`, or hook installer code.
- No unmet goals remain.


=== SSS ARCHITECTURE ITERATION -- 2026-06-05 ===

## 1. Final architecture decision

SSS is a static-analysis-driven security review tool that produces short,
self-contained browser Console PoCs for frontend vulnerabilities. The core
architectural decision is: promoted findings carry a direct fetch-replay or
DOM/storage PoC (at most 12 lines, no global hook installer). Review candidates
carry only a manual plan. The common_console_helper block is never shown to the
user unless at least one promoted playbook actually requires the SSS_POC capture
flow, which is no longer generated.

## 2. What SSS is now designed to be

- A source-code scanner that extracts API call candidates from frontend JS/JSX/HTML.
- A promotion engine that upgrades high-confidence candidates to executable playbooks.
- A playbook generator that emits short, self-contained CONFIRM-guarded fetch replays
  (or 1-2 line DOM/storage PoCs) that can be pasted directly into browser DevTools.
- A review-candidate sieve that demotes low-confidence or unresolvable findings to
  manual_plan with structured guidance (file/function/endpoint, breakpoint hints).

## 3. What SSS is explicitly NOT designed to be

- A fuzzer or runtime attack tool.
- A backend vulnerability scanner.
- A tool that generates destructive (DELETE/refund/withdraw/transfer) payloads.
- A tool that installs global fetch/XHR/axios hooks in promoted playbook PoCs.
- A reporting tool that conflates review candidates with confirmed findings.

## 4. Pipeline summary

source code (ZIP/files)
  -> file filter (exclude build artifacts, vendor, minified)
  -> api_candidate_extractor (extract fetch/axios/$.ajax call sites and UI events)
  -> source_intelligence (build project_understanding: routes, pages, api_inventory)
  -> MockConsolePocAnalyzer / GeminiConsolePocAnalyzer (classify and score candidates)
  -> promotion gate (score >= 5, concrete page/action hints, interceptor-free PoC)
     -> ConsoleVerificationPlaybookSummary (endpoint, function_name, console_code)
  -> review sieve (score < 5, generic action, unresolved placeholder, UNKNOWN endpoint)
     -> ReadableFinding with manual_poc_plan
  -> ReadableAnalysisResult (findings, verification_playbooks, review_candidates,
     common_console_helper=None when all PoCs self-contained, project_understanding)

## 5. Files changed

app/services/poc_templates.py
  - Extended INTERCEPTOR_SIGS to include window.SSS_POC.find(, .replay(, .list(,
    .armMutation( so is_interceptor_free() catches these capture-flow calls.
  - Extended _BASE_URL_EXPR_RE to strip any brace-enclosed token whose name ends
    in _URL, _BASE, _BASEURL, or _BASE_URL (adds {API_URL}, {REACT_APP_API_URL},
    etc.) in normalize_endpoint().

tests/test_console_poc_analysis_service.py
  - Added 12 regression tests covering all four changes (A/B/C/D).

## 6. Key functions changed

poc_templates.py::INTERCEPTOR_SIGS
  Added: 'window.SSS_POC.find(', 'window.SSS_POC.replay(',
         'window.SSS_POC.list(', 'window.SSS_POC.armMutation('

poc_templates.py::_BASE_URL_EXPR_RE
  Extended to match {API_URL}, {REACT_APP_API_URL}, and any {TOKEN_URL} pattern
  in addition to the previously known {API_BASE_URL}, {API_BASE}, {BASE_URL},
  {apiBase} patterns.

console_poc_analysis_service.py::_build_playbook_poc
  Returns None (instead of falling back to SSS_POC capture flow) when
  build_request_replay_poc cannot produce a self-contained PoC.

console_poc_analysis_service.py::_proof_steps
  First item is now always a Navigate-to step (Navigate to <page_hint>) for
  both mutation (POST/PUT/PATCH) and read-only (GET) methods.

## 7. Final verify_goal.py output

PASS  G1a: {API_BASE_URL}/login POST promotes
PASS  G1b: console_code contains fetch("/login"
PASS  G1c: console_code does NOT contain window.SSS_POC.find(
PASS  G1d: console_code contains no helper namespace
PASS  G1e: console_code <=12 lines
PASS  G1f: common_console_helper is not required
PASS  G2a: /api/auction/{item.id}/bid POST promotes
PASS  G2b: console_code contains a REPLACE constant
PASS  G2c: console_code contains template-literal fetch path
PASS  G2d: console_code does NOT contain window.SSS_POC.find(
PASS  G2e: console_code is interceptor-free
PASS  G2f: console_code <=12 lines
PASS  G3a: common_console_helper is None when all PoCs self-contained
PASS  G3b: all promoted PoCs are self-contained (no SSS_POC.find)
PASS  G3c: playbook /api/orders/pay <=12 lines
PASS  G3d: playbook /api/orders/pay interceptor-free
PASS  G3e: ${API_BASE_URL}/admin/add-numbers promotes
PASS  G3f: API_BASE_URL + "/generate-lotto" promotes
PASS  G3g: axios.create({ baseURL }).post("/login") promotes
PASS  G3h: unknown path placeholder remains manual
PASS  G4a: {API_BASE_URL}/admin/refund POST is NOT promoted
PASS  G4b: DELETE /api/user/1 is NOT promoted
PASS  G4c: no promoted PoC code contains destructive action

verify_goal: 23 passed, 0 failed

## 8. Final pytest output

396 passed in 4.03s
(Baseline was 384; 12 new regression tests added)

## 9. Example promoted finding output (structure, not live data)

ConsoleVerificationPlaybookSummary fields:
  id: sha256-based hex ID
  title: 'payment/point request parameter manipulation possible'
  source_path: 'src/PaymentPage.jsx'
  start_line: 3
  end_line: 5
  function_name: 'handlePayment'
  endpoint: '/api/order/123/complete-payment'
  method: 'POST'
  page_hint: 'payment/order page'
  user_action_hint: 'click payment button'
  risk_type: 'Payment/Point Manipulation Candidate'
  confidence: 'medium'
  console_code: CONFIRM-guarded direct fetch replay (at most 12 lines)
  proof_steps: ['Navigate to payment/order page', 'paste the PoC into Console', ...]
  success_criteria: ['response status/content-type/body preview is visible in Console', ...]
  failure_criteria: ['server rejects with 400/401/403', ...]
  evidence_to_capture: ['Console screenshot showing response status/content-type/body preview', ...]
  data_flow: FindingDataFlow(user_action, handler, api_call_or_sink, missing_guard_or_validation)
  breakpoint_plan: BreakpointPlan(file, line, function, when_to_pause, what_variable_to_check)
  poc_injection_plan: PocInjectionPlan(where_to_paste_code, when_to_run, required_user_action)

## 10. Example direct PoC (build_request_replay_poc output format)

For POST /api/order/{orderId}/complete-payment with fields [totalAmount, usePoints]:

  (async () => {
    if (!confirm("[SSS PoC] Run approved POST /api/order/{orderId}/complete-payment?")) return;
    const ORDER_ID = "REPLACE_WITH_ORDER_ID";
    const r = await fetch(`/api/order/${ORDER_ID}/complete-payment`, {
      method: "POST", credentials: "include",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "totalAmount": 1, "usePoints": 1 }),
    });
    console.log('[SSS PoC]', r.status, r.headers.get('content-type'), (await r.text()).slice(0, 500));
  })();

Rules enforced: no global hook, CONFIRM guard for mutations, REPLACE_WITH_* labels
for path params, <= 12 lines total.

## 11. Example review candidate output (structure)

ReadableFinding with:
  title: 'Manual review candidate: payment/point request parameter manipulation possible'
  poc_generation_status: 'manual_plan'
  console_poc.code: None (no runnable code for unconfirmed candidates)
  observational_poc: None (cleared; capture hint only when playbooks exist)
  manual_poc_plan: [
    'File: src/service.js',
    'Function: UNKNOWN',
    'Request: POST /api/orders/123/pay',
    'reconfirm data_flow (method/endpoint/function/sink) from evidence',
    ...
  ]
  verification_notes: [
    'Manual review candidate',
    'Not an automatically confirmed vulnerability',
    'Resolve endpoint/page/action before using PoC',
    'Needs runtime capture before proof',
    'Not a runnable proof yet: user action could not be inferred from source code',
    'playbook_score=-3: no_strong_signals',
  ]

## 12. Remaining limitations

- normalize_endpoint only strips brace-enclosed tokens matching known suffix
  patterns (_URL, _BASE, etc.). Tokens like {BACKEND_HOST} or {SERVER} are not
  stripped and will still block promotion.
- Path parameters use a fixed lookup table; novel param names (e.g. {auctionNo})
  fall back to a generic PARAM constant which may confuse testers.
- The promotion score is a heuristic; edge cases (no button, no function name,
  ambiguous UI event text) may misclassify a promotable finding as review-only.
- Gemini analyzer output is not tested at unit level (requires a live API key).
- DOM XSS detection relies on static sink+source co-location; indirect flows
  through React state or event handlers are not detected.

## 13. Goals that could not be met

None. All 23 verify_goal.py goals pass and all 396 pytest tests pass after adding
the regression tests and extending normalize_endpoint for unknown base-URL prefixes.

=== END SSS ARCHITECTURE ITERATION -- 2026-06-05 ===
