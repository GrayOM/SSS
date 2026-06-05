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
