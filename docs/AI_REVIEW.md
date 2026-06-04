# AI Architecture Review

## Summary

The current engine is a **regex request-scraper + runtime interceptor**, not a
source-to-sink vulnerability analyzer.  This document maps each anti-pattern
to its source location so the redesign can be applied precisely.

---

## Critical Issues

### CI-1: Keyword classification masquerading as vulnerability analysis

**File:** `app/services/console_poc_analysis_service.py`
**Function:** `MockConsolePocAnalyzer._classify_api_candidate` (~line 1570)

```
endpoint contains "payment" OR params contain "amount"
  => label "Payment/Point Manipulation Candidate"  severity=high
```

No data-flow reasoning. Any `axios.post('/api/wallet/charge', {amount})` call
becomes a high-severity finding regardless of whether attacker input can reach
`amount`. This is endpoint-keyword labeling, not security analysis.

---

### CI-2: Global fetch/XHR/axios interceptor as primary PoC output

**File:** `app/services/console_poc_analysis_service.py`

- `_build_common_console_helper` (~line 390): 200+ line IIFE that
  monkey-patches `window.fetch`, `XMLHttpRequest.prototype.open`,
  `axios.interceptors.request.use`, and `window.jQuery.ajax`.
- `_build_network_hook_mutation_poc` (~line 675): per-finding 60-100 line
  IIFE installing targeted `window.fetch` + XHR + axios interceptors.

Both are used as the DEFAULT output for findings, not as fallbacks.
Result: every finding asks the user to paste a 200-line helper, click around
until a request is captured, then replay.  That is brute-force runtime traffic
capture, not static proof-of-exploit.

---

### CI-3: Promotion gated on cosmetic hint quality, not proof quality

**File:** `app/services/console_poc_analysis_service.py`
**Function:** `analyze_console_exploitability` (~line 1909)

```python
should_review = (
    ...
    is_generic_action or is_generic_page or
    (function_name is None and not is_jq_html_promotable and not is_dom_flow) or
    ...
)
```

- A confirmed DOM XSS with `location.hash='<img src=x onerror=alert(1)>'`
  (1 line) is demoted to review because `page_hint == 'target feature page'`.
- A confirmed auth bypass (`sessionStorage.setItem(...)`) is demoted because
  `endpoint == 'UNKNOWN'` (no API call - correct for a storage-auth check).

Proof quality (concrete source-to-sink + runnable short PoC) should gate
promotion, not regex hint cleanliness.

---

### CI-4: LLM prompt requests field-labeling, not flow reasoning

**File:** `app/services/prompt_builder.py`
**Function:** `build_candidate_analysis_prompt` (line 180)

The prompt asks the model to "Evaluate each API call candidate for client-side
validation bypass..."  The response schema has `FindingDataFlow` with
`api_call_or_sink` and `missing_guard_or_validation` but no `source_line`,
no `sink_line`, no step-by-step flow chain.  Without an explicit flow the
model cannot emit a deterministic direct PoC.

---

### CI-5: `_mk_validation_bypass` generates big hook for every concrete endpoint

**File:** `app/services/console_poc_analysis_service.py`
**Function:** `MockConsolePocAnalyzer._mk_validation_bypass` (~line 1645)

```python
poc_code = _build_network_hook_mutation_poc(endpoint, page_hint=page_hint, action_hint=action_hint)
```

Every `axios.post('/api/order/pay', {amount})` with a concrete action hint gets
a 60-line interceptor instead of a 10-line `CONFIRM_AUTHORIZED_TEST`-guarded
direct replay.

---

## Implementation Recommendations

1. Create `app/services/poc_templates.py` with three typed builders:
   - `build_dom_xss_poc(source_expr, sink_expr)` -> 1-2 lines
   - `build_storage_auth_poc(storage, key, field, value)` -> 1 line + reload
   - `build_request_replay_poc(method, endpoint, field, test_value)` -> <=10 lines, CONFIRM-guarded

2. Replace `_build_network_hook_mutation_poc` in `_mk_validation_bypass` with
   `build_request_replay_poc` for concrete non-destructive endpoints.

3. Add `has_short_direct_poc` + `is_confirmed_short_poc` guard to
   `analyze_console_exploitability` so DOM XSS and storage-auth bypass with
   short PoCs are promoted instead of demoted.

4. Use poc_templates builders in playbook `console_code` construction.

5. Update `build_candidate_analysis_prompt` to require `source_line`, `sink_line`,
   and `data_flow_steps` fields in the LLM response.

---

## Files Codex Should Modify

| File | Change |
|---|---|
| `app/services/poc_templates.py` | CREATE - typed PoC builders |
| `app/services/console_poc_analysis_service.py` | Replace interceptor in `_mk_validation_bypass`; fix promotion logic; use templates in playbook builder |
| `app/services/prompt_builder.py` | Require source+sink line chain in LLM response |
| `tests/test_console_poc_analysis_service.py` | Add proof-quality tests; update interceptor-asserting tests |

## Tests Codex Should Add

1. `test_dom_xss_poc_is_at_most_2_lines`
2. `test_dom_xss_promoted_not_demoted_to_review`
3. `test_auth_bypass_poc_is_storage_plus_reload`
4. `test_request_replay_poc_no_global_hook`
5. `test_promoted_playbook_never_has_full_interceptor`
6. `test_poc_templates_ascii_clean`
7. `test_poc_templates_replay_passes_safety_filter`
8. `test_poc_templates_destructive_endpoint_returns_none`

## Push Blockers

None.  No security control is weakened.  The destructive-endpoint block,
ZIP upload guards, content stripping, and ASCII safety filters all remain.
The interceptor is demoted to a discovery fallback, not removed.
