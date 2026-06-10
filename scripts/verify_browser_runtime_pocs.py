#!/usr/bin/env python3
"""Browser-runtime oriented verification for generated SSS Console PoCs.

This verifier intentionally calls the real SSS analysis pipeline and checks
actual promoted ``console_code`` output.  The current local environment does
not provide Playwright or Node.js, so runtime execution is approximated with a
deterministic structural simulation:

- runtime resolvers must be present before fetch()
- fallback guards must appear before mutation fetch()
- payload style must match the source request style
- helper/interceptor code must not appear
- destructive endpoints must not be promoted

When a browser or JS engine is available, this script can be extended to execute
the same generated code against fixture pages.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass

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


def main() -> int:
    print("verify_browser_runtime_pocs: runtime_engine=deterministic_static_simulation")
    print(f"verify_browser_runtime_pocs: node_available={bool(shutil.which('node'))}")
    print(f"verify_browser_runtime_pocs: playwright_available={bool(shutil.which('playwright'))}")

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
    for endpoint, method, label, sources, style in (
        ("/api/order/{auctionItem.orderId}/complete-payment", "POST", "order complete payment", ("location.search", "location.pathname", "DOM selector"), "json"),
        ("/api/user/{sessionData.userId}/wallet/charge", "POST", "wallet charge", ("storage", "location.search", "DOM selector"), "json"),
        ("/api/auction/{item.id}/bid", "POST", "auction bid", ("location.search", "location.pathname", "DOM selector"), "json"),
        ("/api/iamport/verify", "POST", "iamport verify", ("location.search", "DOM selector", "app state"), "json"),
    ):
        pb = exact_playbook(core, endpoint, method)
        check(f"{label}: promoted playbook present", pb is not None, f"endpoints={[p.endpoint for p in core.verification_playbooks]}")
        if pb:
            cases.append(Case(label, pb.endpoint or endpoint, pb.method or method, pb.console_code or "", sources, style))

    verify_pb = exact_playbook(recovery, "/verify-code", "POST")
    check("account recovery verify-code: promoted playbook present", verify_pb is not None)
    if verify_pb:
        cases.append(Case("account recovery verify-code", verify_pb.endpoint or "/verify-code", verify_pb.method or "POST", verify_pb.console_code or "", ("location.search", "DOM selector", "storage", "app state"), "json"))

    form_pb = exact_playbook(general, "/api/payments/evidence", "POST")
    check("FormData payment evidence: promoted playbook present", form_pb is not None)
    if form_pb:
        cases.append(Case("FormData payment evidence", form_pb.endpoint or "/api/payments/evidence", form_pb.method or "POST", form_pb.console_code or "", ("FormData", "location.search", "DOM selector"), "formdata"))

    url_pb = exact_playbook(urlencoded, "/verify-code", "POST")
    check("URLSearchParams verify-code: promoted playbook present", url_pb is not None, f"endpoints={[p.endpoint for p in urlencoded.verification_playbooks]}")
    if url_pb:
        cases.append(Case("URLSearchParams verify-code", url_pb.endpoint or "/verify-code", url_pb.method or "POST", url_pb.console_code or "", ("location.search", "DOM selector", "storage", "app state"), "urlencoded"))

    dom_pb = next((p for p in dom_event.verification_playbooks if p.method == "DOM"), None)
    check("DOM XSS event.data: promoted playbook present", dom_pb is not None)
    if dom_pb:
        code = dom_pb.console_code or ""
        check("DOM XSS event.data: source-specific postMessage PoC", "window.postMessage" in code, code)
        check("DOM XSS event.data: helper-free", helper_free(code), code)
        check("DOM XSS event.data: syntax sanity", syntax_like_js(code), code)

    storage_pb = next((p for p in general.verification_playbooks if p.method == "STORAGE"), None)
    check("storage/auth branch: promoted playbook present", storage_pb is not None)
    if storage_pb:
        code = storage_pb.console_code or ""
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

    print("")
    print("browser_runtime_summary:")
    print(f"  promoted_core={len(core.verification_playbooks)}")
    print(f"  promoted_recovery={len(recovery.verification_playbooks)}")
    print(f"  promoted_generalization={len(general.verification_playbooks)}")
    print("  execution_limit=No Playwright/Node engine available; structural runtime simulation used.")
    print("")
    print(f"verify_browser_runtime_pocs: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
