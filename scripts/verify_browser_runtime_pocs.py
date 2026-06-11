#!/usr/bin/env python3
"""Browser-runtime oriented verification for generated SSS Console PoCs.

This verifier intentionally calls the real SSS analysis pipeline and checks
actual promoted ``console_code`` output.  When Playwright is installed with a
browser, it executes representative generated PoCs inside controlled fixture
pages.  Otherwise it falls back to deterministic structural simulation:

- runtime resolvers must be present before fetch()
- fallback guards must appear before mutation fetch()
- payload style must match the source request style
- helper/interceptor code must not appear
- destructive endpoints must not be promoted
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import MockConsolePocAnalyzer, analyze_console_exploitability
from app.services.poc_templates import INTERCEPTOR_SIGS, build_request_replay_poc
from scripts.verify_generalization import public_pattern_fixture
from scripts.verify_realistic_output import realistic_core_fixture, recovery_login_fixture


PASS = 0
FAIL = 0

FORBIDDEN = (
    "window.SSS_POC",
    "window.SSS_REVIEW_POC",
    "common_console_helper",
    "armMutation",
    "window.fetch = async function",
    "XMLHttpRequest.prototype",
    "axios.interceptors.request.use",
) + INTERCEPTOR_SIGS


def fc(path: str, content: str) -> FileContent:
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return FileContent(path=path, extension=ext, size=len(content), priority=1, reason_code="INCLUDED", content_hash="browser-runtime", content=content)


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        print(f"PASS  {name}")
        PASS += 1
    else:
        print(f"FAIL  {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


def line_index(code: str, needle: str) -> int:
    for idx, line in enumerate(code.splitlines()):
        if needle in line:
            return idx
    return -1


def syntax_like_js(code: str) -> bool:
    """Cheap syntax sanity check used when no JS runtime is installed."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    in_single = False
    in_double = False
    in_backtick = False
    escaped = False
    for ch in code:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "'" and not in_double and not in_backtick:
            in_single = not in_single
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            continue
        if ch == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            continue
        if in_single or in_double or in_backtick:
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in pairs.values():
            if not stack or stack.pop() != ch:
                return False
    return not stack and not in_single and not in_double and not in_backtick


def helper_free(code: str) -> bool:
    return not any(sig and sig in code for sig in FORBIDDEN)


def fallback_guard_before_fetch(code: str) -> bool:
    if "REPLACE_WITH_" not in code:
        return True
    guard = line_index(code, "Fill required runtime values before sending")
    fetch = line_index(code, "fetch(")
    return guard >= 0 and fetch >= 0 and guard < fetch


def mutation_shape(code: str, method: str) -> bool:
    if method not in {"POST", "PUT", "PATCH"}:
        return True
    confirm_idx = line_index(code, "confirm(")
    fetch_idx = line_index(code, "fetch(")
    return confirm_idx >= 0 and fetch_idx >= 0 and confirm_idx < fetch_idx


def runtime_resolver_sources(code: str) -> list[str]:
    sources: list[str] = []
    if "location.pathname.match" in code:
        sources.append("location.pathname")
    if "URLSearchParams(location.search)" in code:
        sources.append("location.search")
    if "document.querySelector" in code:
        sources.append("DOM selector")
    if "sessionStorage.getItem" in code or "localStorage.getItem" in code:
        sources.append("storage")
    if "window.__INITIAL_STATE__" in code:
        sources.append("app state")
    if "FormData" in code:
        sources.append("FormData")
    if "window.postMessage" in code:
        sources.append("postMessage")
    if "Storage.setItem" in code or ".setItem(" in code:
        sources.append("storage mutation")
    return sorted(set(sources))


def exact_playbook(result, endpoint: str, method: str | None = None):
    for pb in result.verification_playbooks:
        if pb.endpoint == endpoint and (method is None or pb.method == method):
            return pb
    return None


def contains_playbook(result, endpoint_part: str, method: str | None = None):
    for pb in result.verification_playbooks:
        if endpoint_part in (pb.endpoint or "") and (method is None or pb.method == method):
            return pb
    return None


@dataclass
class Case:
    label: str
    endpoint: str
    method: str
    code: str
    expected_sources: tuple[str, ...]
    payload_style: str = "json"
    expected_url_part: str | None = None
    expected_body_keys: tuple[str, ...] = ()
    resolved_url: str = "https://sss.test/orders/ORDER-123/auction/ITEM-456/users/USER-789/payments/PAY-123?orderId=ORDER-123&itemId=ITEM-456&userId=USER-789&paymentId=PAY-123&imp_uid=IMP-123&merchant_uid=MERCHANT-456&email=assessor%40example.test&code=654321"


def validate_case(case: Case) -> None:
    code = case.code
    target = f"{case.method} {case.endpoint}"
    check(f"{case.label}: console_code exists", bool(code.strip()))
    check(f"{case.label}: syntax sanity", syntax_like_js(code), code)
    check(f"{case.label}: helper/interceptor-free", helper_free(code), code)
    check(f"{case.label}: mutation confirm guard", mutation_shape(code, case.method), code)
    if case.method in {"POST", "PUT", "PATCH"}:
        check(f"{case.label}: fallback guard before fetch", fallback_guard_before_fetch(code), code)
    if case.method == "GET":
        check(f"{case.label}: GET credentials include", '{ credentials: "include" }' in code, code)
    if case.method in {"POST", "PUT", "PATCH", "GET"}:
        check(f"{case.label}: direct fetch present", "fetch(" in code, code)
        check(f"{case.label}: response preview logging", "r.headers.get('content-type')" in code and ".slice(0, 500)" in code, code)
    sources = runtime_resolver_sources(code)
    for source in case.expected_sources:
        check(f"{case.label}: uses runtime source {source}", source in sources, f"sources={sources}\n{code}")
    if case.payload_style == "json":
        check(f"{case.label}: JSON payload style", "JSON.stringify" in code and "application/json" in code, code)
    elif case.payload_style == "formdata":
        check(f"{case.label}: FormData payload style", "const fd = new FormData();" in code and "body: fd" in code, code)
        check(f"{case.label}: FormData does not force JSON content-type", "application/json" not in code, code)
    elif case.payload_style == "urlencoded":
        check(f"{case.label}: URLSearchParams payload style", "const body = new URLSearchParams();" in code and "body.toString()" in code, code)
        check(f"{case.label}: URL encoded content-type", "application/x-www-form-urlencoded" in code, code)
    if "REPLACE_WITH_" in code and case.method in {"POST", "PUT", "PATCH"}:
        guard_idx = line_index(code, "Fill required runtime values before sending")
        confirm_idx = line_index(code, "confirm(")
        fetch_idx = line_index(code, "fetch(")
        check(f"{case.label}: unresolved fallback stops before confirm/fetch", 0 <= guard_idx < confirm_idx < fetch_idx, code)
    check(f"{case.label}: usable target", bool(target and "UNKNOWN" not in target), target)


def _playwright_import():
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
        return sync_playwright, PlaywrightError
    except Exception:
        return None, None


def playwright_runtime_available() -> tuple[bool, str]:
    sync_playwright, PlaywrightError = _playwright_import()
    if not sync_playwright:
        return False, "python playwright package is not installed"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True, "playwright chromium launch succeeded"
    except Exception as exc:  # pragma: no cover - depends on local browsers
        if PlaywrightError and isinstance(exc, PlaywrightError):
            return False, f"playwright browser unavailable: {exc}"
        return False, f"playwright launch failed: {exc}"


def _fixture_html(include_runtime_values: bool = True) -> str:
    if not include_runtime_values:
        return """<!doctype html>
<html>
<body>
  <div id="messageSink"></div>
</body>
</html>"""
    return """<!doctype html>
<html>
<body>
  <form id="verify">
    <input name="orderId" value="ORDER-DOM">
    <input name="itemId" value="ITEM-DOM">
    <input name="userId" value="USER-DOM">
    <input name="paymentId" value="PAY-DOM">
    <input name="imp_uid" value="IMP-DOM">
    <input name="merchant_uid" value="MERCHANT-DOM">
    <input name="email" type="email" value="assessor-dom@example.test">
    <input name="code" value="111222">
    <input name="verifyCode" value="333444">
  </form>
  <div id="target"
       data-order-id="ORDER-DATA"
       data-item-id="ITEM-DATA"
       data-user-id="USER-DATA"
       data-payment-id="PAY-DATA"
       data-imp-uid="IMP-DATA"
       data-merchant-uid="MERCHANT-DATA"
       data-code="555666"></div>
  <div id="messageSink"></div>
  <script>
    window.addEventListener('message', function (event) {
      document.getElementById('messageSink').innerHTML = event.data;
    });
  </script>
</body>
</html>"""


def _install_fetch_mock(page) -> None:
    page.add_init_script(
        """
window.__sssFetchCalls = [];
window.__sssConfirmMessages = [];
window.__sssPostedMessages = [];
const originalPostMessage = window.postMessage.bind(window);
window.postMessage = function(message, targetOrigin, transfer) {
  window.__sssPostedMessages.push({ message, targetOrigin });
  return originalPostMessage(message, targetOrigin, transfer);
};
window.fetch = async function(input, init = {}) {
  const url = typeof input === 'string' ? input : (input && input.url) || String(input);
  const method = String((init && init.method) || 'GET').toUpperCase();
  const headers = init && init.headers || {};
  let bodyKind = null;
  let bodyText = null;
  let formEntries = null;
  const body = init && init.body;
  if (body instanceof FormData) {
    bodyKind = 'FormData';
    formEntries = {};
    for (const [k, v] of body.entries()) formEntries[k] = v && v.name ? `[File:${v.name}]` : String(v);
  } else if (body instanceof URLSearchParams) {
    bodyKind = 'URLSearchParams';
    bodyText = body.toString();
  } else if (typeof body === 'string') {
    bodyKind = 'string';
    bodyText = body;
  } else if (body !== undefined && body !== null) {
    bodyKind = Object.prototype.toString.call(body);
    bodyText = String(body);
  }
  window.__sssFetchCalls.push({
    url,
    method,
    credentials: init && init.credentials,
    headers,
    bodyKind,
    bodyText,
    formEntries
  });
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' }
  });
};
window.confirm = function(message) {
  window.__sssConfirmMessages.push(String(message));
  return true;
};
"""
    )


def _prepare_runtime_page(browser, case: Case, resolved: bool):
    page = browser.new_page()
    _install_fetch_mock(page)
    html = _fixture_html(include_runtime_values=resolved)
    page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body=html))
    url = case.resolved_url if resolved else "https://sss.test/blank"
    page.goto(url)
    page.set_content(html)
    if resolved:
        page.evaluate(
            """
() => {
  sessionStorage.setItem('user', JSON.stringify({
    id: 'USER-STORAGE',
    userId: 'USER-STORAGE',
    email: 'storage@example.test',
    phone: '01012345678'
  }));
  localStorage.setItem('user', JSON.stringify({
    id: 'USER-LOCAL',
    userId: 'USER-LOCAL',
    email: 'local@example.test'
  }));
  localStorage.setItem('token', 'TOKEN-LOCAL');
  window.__INITIAL_STATE__ = {
    orderId: 'ORDER-STATE',
    itemId: 'ITEM-STATE',
    productId: 'PRODUCT-STATE',
    paymentId: 'PAY-STATE',
    impUid: 'IMP-STATE',
    merchantUid: 'MERCHANT-STATE',
    code: '999000',
    user: { id: 'USER-STATE', email: 'state@example.test', phone: '01000000000' }
  };
}
"""
        )
    else:
        page.evaluate(
            """
() => {
  sessionStorage.clear();
  localStorage.clear();
  delete window.__INITIAL_STATE__;
}
"""
        )
    return page


def _run_console_code(page, code: str) -> dict[str, Any]:
    page.evaluate("(code) => eval(code)", code)
    return page.evaluate(
        """() => ({
  fetchCalls: window.__sssFetchCalls || [],
  confirmMessages: window.__sssConfirmMessages || [],
  postedMessages: window.__sssPostedMessages || [],
  sessionUser: sessionStorage.getItem('user'),
  localUserType: localStorage.getItem('userType'),
  messageSinkHtml: document.querySelector('#messageSink')?.innerHTML || ''
})"""
    )


def _parse_headers(headers: Any) -> dict[str, str]:
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


def _validate_playwright_case(browser, case: Case) -> None:
    if case.method in {"POST", "PUT", "PATCH"} and "REPLACE_WITH_" in case.code:
        unresolved_page = _prepare_runtime_page(browser, case, resolved=False)
        try:
            no_runtime_sources = unresolved_page.evaluate(
                """() => ({
  search: location.search,
  path: location.pathname,
  inputs: document.querySelectorAll('input[value]').length,
  dataAttrs: document.querySelectorAll('[data-order-id], [data-item-id], [data-user-id], [data-payment-id], [data-imp-uid], [data-merchant-uid], [data-code]').length,
  sessionUser: sessionStorage.getItem('user'),
  localUser: localStorage.getItem('user'),
  state: window.__INITIAL_STATE__
})"""
            )
            check(
                f"{case.label}: Playwright unresolved page has no runtime source values",
                no_runtime_sources.get("search") == ""
                and no_runtime_sources.get("path") == "/blank"
                and no_runtime_sources.get("inputs") == 0
                and no_runtime_sources.get("dataAttrs") == 0
                and no_runtime_sources.get("sessionUser") is None
                and no_runtime_sources.get("localUser") is None
                and no_runtime_sources.get("state") is None,
                json.dumps(no_runtime_sources),
            )
            unresolved = _run_console_code(unresolved_page, case.code)
            check(f"{case.label}: Playwright unresolved fallback blocks fetch", len(unresolved["fetchCalls"]) == 0, json.dumps(unresolved))
            check(f"{case.label}: Playwright unresolved fallback blocks confirm", len(unresolved["confirmMessages"]) == 0, json.dumps(unresolved))
        finally:
            unresolved_page.close()

    page = _prepare_runtime_page(browser, case, resolved=True)
    try:
        result = _run_console_code(page, case.code)
    finally:
        page.close()

    if case.method in {"POST", "PUT", "PATCH", "GET"}:
        calls = result["fetchCalls"]
        check(f"{case.label}: Playwright fetch called with runtime values", len(calls) == 1, json.dumps(result))
        if not calls:
            return
        call = calls[0]
        expected_part = case.expected_url_part or case.endpoint.split("{", 1)[0]
        check(f"{case.label}: Playwright URL resolved", expected_part in call["url"] and "REPLACE_WITH_" not in call["url"], json.dumps(call))
        check(f"{case.label}: Playwright method", call["method"] == case.method, json.dumps(call))
        check(f"{case.label}: Playwright credentials include", call["credentials"] == "include", json.dumps(call))
        if case.method in {"POST", "PUT", "PATCH"}:
            check(f"{case.label}: Playwright confirm accepted", len(result["confirmMessages"]) == 1, json.dumps(result))
        if case.payload_style == "json":
            headers = _parse_headers(call["headers"])
            check(f"{case.label}: Playwright JSON content-type", headers.get("content-type") == "application/json", json.dumps(call))
            try:
                parsed = json.loads(call["bodyText"] or "{}")
            except json.JSONDecodeError:
                parsed = {}
            for key in case.expected_body_keys:
                check(f"{case.label}: Playwright JSON body key {key}", key in parsed and not str(parsed[key]).startswith("REPLACE_WITH_"), json.dumps(parsed))
        elif case.payload_style == "formdata":
            check(f"{case.label}: Playwright FormData body", call["bodyKind"] == "FormData", json.dumps(call))
            for key in case.expected_body_keys:
                check(f"{case.label}: Playwright FormData key {key}", key in (call["formEntries"] or {}), json.dumps(call))
            headers = _parse_headers(call["headers"])
            check(f"{case.label}: Playwright FormData no forced JSON content-type", headers.get("content-type") != "application/json", json.dumps(call))
        elif case.payload_style == "urlencoded":
            headers = _parse_headers(call["headers"])
            check(f"{case.label}: Playwright URLSearchParams content-type", headers.get("content-type") == "application/x-www-form-urlencoded", json.dumps(call))
            body_text = call["bodyText"] or ""
            for key in case.expected_body_keys:
                check(f"{case.label}: Playwright URLSearchParams key {key}", f"{key}=" in body_text, body_text)


def run_playwright_checks(cases: list[Case], dom_code: str | None, storage_code: str | None) -> None:
    available, reason = playwright_runtime_available()
    check("Playwright availability check completed", True, reason)
    if not available:
        print(f"verify_browser_runtime_pocs: playwright_execution=skipped ({reason})")
        return

    sync_playwright, _ = _playwright_import()
    assert sync_playwright is not None
    print("verify_browser_runtime_pocs: playwright_execution=enabled")
    with sync_playwright() as p:  # pragma: no cover - requires local browser
        browser = p.chromium.launch(headless=True)
        try:
            for case in cases:
                _validate_playwright_case(browser, case)
            if dom_code:
                page = _prepare_runtime_page(browser, Case("DOM XSS event.data", "DOM", "DOM", dom_code, ()), resolved=True)
                try:
                    result = _run_console_code(page, dom_code)
                    sink_reached = True
                    try:
                        page.wait_for_function(
                            """() => {
  const html = document.querySelector('#messageSink')?.innerHTML || '';
  return html.includes('<img') && html.includes('onerror') && html.includes('console.log(1)');
}""",
                            timeout=3000,
                        )
                    except Exception:
                        sink_reached = False
                    sink_html = page.evaluate("() => document.querySelector('#messageSink')?.innerHTML || ''")
                    check("DOM XSS event.data: Playwright postMessage called", bool(result["postedMessages"]), json.dumps(result))
                    if result["postedMessages"]:
                        check("DOM XSS event.data: Playwright source-specific payload", "onerror=console.log(1)" in result["postedMessages"][0]["message"], json.dumps(result))
                    semantic_sink_payload = all(part in sink_html for part in ("<img", "onerror", "console.log(1)"))
                    check("DOM XSS event.data: Playwright payload reaches sink", sink_reached and semantic_sink_payload, sink_html)
                finally:
                    page.close()
            if storage_code:
                page = _prepare_runtime_page(browser, Case("storage/auth branch", "STORAGE", "STORAGE", storage_code, ()), resolved=True)
                try:
                    # The real generated PoC reloads after storage mutation.
                    # For verifier inspection, preserve the source-specific
                    # storage write and replace only reload with a marker so
                    # the execution context survives long enough to assert.
                    inspectable_storage_code = storage_code.replace("location.reload();", "window.__sssReloadCalled = true;")
                    _run_console_code(page, inspectable_storage_code)
                    stored = page.evaluate("() => sessionStorage.getItem('user') || localStorage.getItem('userType')")
                    check("storage/auth branch: Playwright storage updated", bool(stored and "ADMIN" in stored), str(stored))
                    reload_called = page.evaluate("() => Boolean(window.__sssReloadCalled)")
                    check("storage/auth branch: Playwright reload behavior represented", reload_called, inspectable_storage_code)
                finally:
                    page.close()
        finally:
            browser.close()


def main() -> int:
    available, reason = playwright_runtime_available()
    print(f"verify_browser_runtime_pocs: runtime_engine={'playwright+deterministic_static_simulation' if available else 'deterministic_static_simulation'}")
    print(f"verify_browser_runtime_pocs: node_available={bool(shutil.which('node'))}")
    print(f"verify_browser_runtime_pocs: playwright_available={available}")
    print(f"verify_browser_runtime_pocs: playwright_status={reason}")

    analyzer = MockConsolePocAnalyzer()
    core = analyze_console_exploitability(realistic_core_fixture(), analyzer=analyzer)
    recovery = analyze_console_exploitability(recovery_login_fixture(), analyzer=analyzer)
    general = analyze_console_exploitability(public_pattern_fixture(), analyzer=analyzer)
    urlencoded = analyze_console_exploitability([
        fc(
            "src/VerifyCode.js",
            """
function verifyCode() {
  const body = new URLSearchParams();
  body.set('email', document.querySelector('[name=email]').value);
  body.set('code', document.querySelector('[name=code]').value);
  fetch('/verify-code', { method: 'POST', body });
}
document.querySelector('#verify').addEventListener('click', verifyCode);
""",
        )
    ], analyzer=analyzer)
    dom_event = analyze_console_exploitability([
        fc("src/MessagePreview.js", "window.addEventListener('message', event => { document.body.innerHTML = event.data; });")
    ], analyzer=analyzer)

    cases: list[Case] = []
    for endpoint, method, label, sources, style, expected_url_part, body_keys in (
        ("/api/order/{auctionItem.orderId}/complete-payment", "POST", "order complete payment", ("location.search", "location.pathname", "DOM selector"), "json", "/api/order/ORDER-123/complete-payment", ("amount", "orderId")),
        ("/api/user/{sessionData.userId}/wallet/charge", "POST", "wallet charge", ("storage", "location.search", "DOM selector"), "json", "/api/user/USER-STORAGE/wallet/charge", ("amount", "userId")),
        ("/api/auction/{item.id}/bid", "POST", "auction bid", ("location.search", "location.pathname", "DOM selector"), "json", "/api/auction/ITEM-456/bid", ("amount", "itemId")),
        ("/api/iamport/verify", "POST", "iamport verify", ("location.search", "DOM selector", "app state"), "json", "/api/iamport/verify", ("amount", "imp_uid", "merchant_uid")),
    ):
        pb = exact_playbook(core, endpoint, method)
        check(f"{label}: promoted playbook present", pb is not None, f"endpoints={[p.endpoint for p in core.verification_playbooks]}")
        if pb:
            cases.append(Case(label, pb.endpoint or endpoint, pb.method or method, pb.console_code or "", sources, style, expected_url_part, body_keys))

    verify_pb = exact_playbook(recovery, "/verify-code", "POST")
    check("account recovery verify-code: promoted playbook present", verify_pb is not None)
    if verify_pb:
        cases.append(Case("account recovery verify-code", verify_pb.endpoint or "/verify-code", verify_pb.method or "POST", verify_pb.console_code or "", ("location.search", "DOM selector", "storage", "app state"), "json", "/verify-code", ("email", "code")))

    form_pb = exact_playbook(general, "/api/payments/evidence", "POST")
    check("FormData payment evidence: promoted playbook present", form_pb is not None)
    if form_pb:
        cases.append(Case("FormData payment evidence", form_pb.endpoint or "/api/payments/evidence", form_pb.method or "POST", form_pb.console_code or "", ("FormData", "location.search", "DOM selector"), "formdata", "/api/payments/evidence", ("amount", "paymentId")))

    url_pb = exact_playbook(urlencoded, "/verify-code", "POST")
    check("URLSearchParams verify-code: promoted playbook present", url_pb is not None, f"endpoints={[p.endpoint for p in urlencoded.verification_playbooks]}")
    if url_pb:
        cases.append(Case("URLSearchParams verify-code", url_pb.endpoint or "/verify-code", url_pb.method or "POST", url_pb.console_code or "", ("location.search", "DOM selector", "storage", "app state"), "urlencoded", "/verify-code", ("email", "code")))

    dom_pb = next((p for p in dom_event.verification_playbooks if p.method == "DOM"), None)
    dom_code: str | None = None
    check("DOM XSS event.data: promoted playbook present", dom_pb is not None)
    if dom_pb:
        code = dom_pb.console_code or ""
        dom_code = code
        check("DOM XSS event.data: source-specific postMessage PoC", "window.postMessage" in code, code)
        check("DOM XSS event.data: helper-free", helper_free(code), code)
        check("DOM XSS event.data: syntax sanity", syntax_like_js(code), code)

    storage_pb = next((p for p in general.verification_playbooks if p.method == "STORAGE"), None)
    storage_code: str | None = None
    check("storage/auth branch: promoted playbook present", storage_pb is not None)
    if storage_pb:
        code = storage_pb.console_code or ""
        storage_code = code
        check("storage/auth branch: meaningful target", storage_pb.endpoint not in {None, "", "UNKNOWN"}, storage_pb.endpoint or "")
        check("storage/auth branch: storage mutation source", "Storage.setItem" in code or ".setItem(" in code, code)
        check("storage/auth branch: helper-free", helper_free(code), code)
        check("storage/auth branch: syntax sanity", syntax_like_js(code), code)

    for case in cases:
        validate_case(case)

    get_code = build_request_replay_poc("GET", "/api/order/{orderId}")
    check("GET PoC builder: generated", get_code is not None)
    if get_code:
        validate_case(Case("GET IDOR-style read", "/api/order/{orderId}", "GET", get_code, ("location.search", "location.pathname", "DOM selector"), "none"))

    unresolved_code = build_request_replay_poc("POST", "/api/order/{orderId}/complete-payment", fields=["orderId", "amount"])
    check("fallback simulation: mutation PoC generated", unresolved_code is not None)
    if unresolved_code:
        check("fallback simulation: guard exists before fetch", fallback_guard_before_fetch(unresolved_code), unresolved_code)
        check("fallback simulation: fetch is blocked when placeholder remains", "String(v).startsWith(\"REPLACE_WITH_\")" in unresolved_code, unresolved_code)

    destructive = [p for p in core.verification_playbooks + general.verification_playbooks if p.method == "DELETE" or any(token in (p.endpoint or "").lower() for token in ("refund", "transfer", "withdraw", "bulk", "remove", "delete"))]
    check("destructive endpoints not promoted", not destructive, str([(p.method, p.endpoint) for p in destructive]))

    run_playwright_checks(cases, dom_code, storage_code)

    print("")
    print("browser_runtime_summary:")
    print(f"  promoted_core={len(core.verification_playbooks)}")
    print(f"  promoted_recovery={len(recovery.verification_playbooks)}")
    print(f"  promoted_generalization={len(general.verification_playbooks)}")
    print(f"  playwright_execution={'enabled' if available else 'skipped'}")
    if not available:
        print(f"  execution_limit={reason}; structural runtime simulation used.")
    print("")
    print(f"verify_browser_runtime_pocs: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
