#!/usr/bin/env python3
"""
verify_realistic_output.py -- realistic output-shape validation for SSS.

This script validates full ReadableAnalysisResult objects, not isolated helper
functions. It uses representative frontend source fixtures that model the
browser-console PoC workflow SSS is intended to support.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.schemas import FileContent, ReadableAnalysisResult
from app.services.console_poc_analysis_service import MockConsolePocAnalyzer, analyze_console_exploitability
from app.services.poc_templates import INTERCEPTOR_SIGS

PASS = 0
FAIL = 0

FORBIDDEN_PROMOTED = (
    "window.SSS_POC",
    "window.SSS_REVIEW_POC",
    "common_console_helper",
    "armMutation",
    "capture/replay",
    "install helper",
    "install common_console_helper",
    "after installing PoC",
) + INTERCEPTOR_SIGS

FORBIDDEN_PROOF_TEXT = (
    "install helper",
    "install common_console_helper",
    "common_console_helper",
    "window.SSS_POC",
    "armMutation",
    "capture/replay",
    "capture flow",
    "replay helper",
    "after installing PoC",
)


def fc(path: str, content: str) -> FileContent:
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return FileContent(
        path=path,
        extension=ext,
        size=len(content),
        priority=1,
        reason_code="INCLUDED",
        content_hash="realistic",
        content=content,
    )


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        print(f"PASS  {name}")
        PASS += 1
    else:
        print(f"FAIL  {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


def non_empty_lines(code: str | None) -> int:
    return len([line for line in (code or "").splitlines() if line.strip()])


def find_playbook(result: ReadableAnalysisResult, endpoint_needle: str):
    return next((p for p in result.verification_playbooks if endpoint_needle in (p.endpoint or "")), None)


def all_review_text(result: ReadableAnalysisResult) -> str:
    parts: list[str] = []
    for f in result.review_candidates:
        parts.extend([f.title, f.summary, f.poc_generation_status or "", f.poc_generation_reason or ""])
        parts.extend(f.verification_notes or [])
        if f.console_poc:
            parts.extend([f.console_poc.description, f.console_poc.code or "", f.console_poc.expected_result])
        if f.observational_poc:
            parts.extend([f.observational_poc.description, f.observational_poc.code or "", f.observational_poc.expected_result])
        parts.extend(f.manual_poc_plan or [])
    return "\n".join(str(x) for x in parts if x)


def validate_promoted_shape(result: ReadableAnalysisResult, label: str) -> None:
    check(f"{label}: common_console_helper hidden for direct promoted PoCs", result.common_console_helper is None)
    check(f"{label}: at least one promoted playbook", len(result.verification_playbooks) > 0)
    for pb in result.verification_playbooks:
        code = pb.console_code or ""
        target = f"{pb.method} {pb.endpoint}"
        check(f"{label}: {target} console_code exists", bool(code.strip()))
        check(f"{label}: {target} uses direct fetch or direct DOM/storage code", "fetch(" in code or "location." in code or "Storage.setItem" in code)
        found_forbidden = [sig for sig in FORBIDDEN_PROMOTED if sig and sig in code]
        check(f"{label}: {target} helper/interceptor-free", not found_forbidden, f"found={found_forbidden}, code={code}")
        if pb.method in {"POST", "PUT", "PATCH"}:
            check(f"{label}: {target} mutation has confirm guard", "confirm(" in code)
        check(f"{label}: {target} <= 12 non-empty lines", non_empty_lines(code) <= 12, f"lines={non_empty_lines(code)}\n{code}")
        check(f"{label}: {target} source location is concrete", bool(pb.source_path) and pb.source_path != "N/A" and isinstance(pb.start_line, int))
        proof_text = "\n".join(
            (pb.setup_steps or [])
            + (pb.proof_steps or [])
            + (pb.success_criteria or [])
            + (pb.failure_criteria or [])
            + (pb.evidence_to_capture or [])
            + ([pb.breakpoint_plan.when_to_pause, pb.breakpoint_plan.what_variable_or_request_to_check] if pb.breakpoint_plan else [])
        )
        found_text = [sig for sig in FORBIDDEN_PROOF_TEXT if sig in proof_text]
        check(f"{label}: {target} proof text has no helper flow", not found_text, f"found={found_text}")


def validate_review_shape(result: ReadableAnalysisResult, label: str) -> None:
    for rc in result.review_candidates:
        code = (rc.console_poc.code or "") if rc.console_poc else ""
        if rc.poc_generation_status == "manual_plan":
            check(f"{label}: manual review candidate has no runnable console_poc code", not code.strip(), rc.title)
        check(f"{label}: review source location preserved", bool(rc.evidence and rc.evidence[0].source_path), rc.title)
        check(f"{label}: review candidate not confirmed", rc.status in {"review_candidate", "raw_signal"}, f"{rc.status}: {rc.title}")


def realistic_core_fixture() -> list[FileContent]:
    return [
        fc(
            "src/AuctionPage.jsx",
            """
function AuctionPage({ item }) {
  function handleBid() {
    axios.post(`/api/auction/${item.id}/bid`, { amount, itemId: item.id });
  }
  return <button onClick={handleBid}>Bid</button>;
}
""",
        ),
        fc(
            "src/WalletPage.jsx",
            """
function WalletPage({ sessionData }) {
  function handlePointCharge() {
    axios.post(`/api/user/${sessionData.userId}/wallet/charge`, { amount, userId: sessionData.userId });
  }
  return <button onClick={handlePointCharge}>Charge wallet</button>;
}
""",
        ),
        fc(
            "src/OrderPage.jsx",
            """
function OrderPage({ auctionItem }) {
  function handlePayment() {
    axios.post(`/api/order/${auctionItem.orderId}/complete-payment`, { amount, orderId: auctionItem.orderId });
  }
  return <button onClick={handlePayment}>Complete payment</button>;
}
""",
        ),
        fc(
            "src/StripeCheckout.jsx",
            """
function StripeCheckout() {
  function handleStripeCheckout() {
    axios.post('/api/stripe/create-checkout-session', { amount, productId, quantity });
  }
  return <button onClick={handleStripeCheckout}>Checkout</button>;
}
""",
        ),
        fc(
            "src/IamportPage.jsx",
            """
function IamportPage() {
  function requestIamportPrepare() {
    axios.post('/api/iamport/prepare', { merchant_uid, orderId, amount });
  }
  function requestIamportPay() {
    axios.post('/api/iamport/verify', { imp_uid, merchant_uid, amount });
  }
  return <><button onClick={requestIamportPrepare}>Pay</button><button onClick={requestIamportPay}>Pay</button></>;
}
""",
        ),
        fc(
            "src/SessionNoise.jsx",
            """
function loadSession() {
  axios.get('/api/user/session');
  fetch('/session/init');
  fetch('/header/recommend_search.do');
  fetch('/api/search?keyword=x');
}
""",
        ),
        fc(
            "src/AdminDanger.jsx",
            """
function deleteUser() {
  axios.delete('/api/user/1');
}
function refundOrder() {
  axios.post('/admin/refund', { orderId, amount });
}
<button onClick={deleteUser}>Delete</button>
<button onClick={refundOrder}>Refund</button>
""",
        ),
    ]


def recovery_login_fixture() -> list[FileContent]:
    return [
        fc(
            "src/FindPassword.jsx",
            """
function FindPassword() {
  function sendVerificationCode() {
    axios.post('/send-verification', { email });
  }
  function verifyCode() {
    axios.post('/verify-code', { email, code });
  }
  return <><button onClick={sendVerificationCode}>Send code</button><button onClick={verifyCode}>Verify</button></>;
}
""",
        ),
        fc(
            "src/LoginPage.jsx",
            """
function LoginPage() {
  function handleLogin() {
    axios.post('{API_BASE_URL}/login', { email, password });
  }
  return <button onClick={handleLogin}>Login</button>;
}
""",
        ),
    ]


def route_param_fixture() -> list[FileContent]:
    return [
        fc("src/Item.jsx", "function handleBid(){axios.post('/api/auction/{item.id}/bid',{amount})}\n<button onClick={handleBid}>Bid</button>"),
        fc("src/User.jsx", "function updateUser(){axios.patch('/api/users/{userId}/role',{role})}\n<button onClick={updateUser}>Save</button>"),
        fc("src/CurrentUser.jsx", "function updateMe(){axios.patch('/api/users/{currentUserId}/profile',{status})}\n<button onClick={updateMe}>Save</button>"),
        fc("src/Wallet.jsx", "function handlePointCharge(){axios.post('/api/user/{sessionData.userId}/wallet/charge',{amount,userId})}\n<button onClick={handlePointCharge}>Charge wallet</button>"),
        fc("src/Order.jsx", "function handlePayment(){axios.post('/api/order/{auctionItem.orderId}/complete-payment',{amount,orderId})}\n<button onClick={handlePayment}>Pay now</button>"),
        fc("src/Order2.jsx", "function submitOrder(){axios.post('/api/order/{orderId}/complete-payment',{amount,orderId})}\n<button onClick={submitOrder}>Pay now</button>"),
        fc("src/Product.jsx", "function buyProduct(){axios.post('/api/products/{productId}/purchase',{quantity,productId})}\n<button onClick={buyProduct}>Purchase</button>"),
    ]


def destructive_fixture() -> list[FileContent]:
    return [
        fc("src/Delete.jsx", "function handleDelete(){axios.delete('/api/user/1')}\n<button onClick={handleDelete}>Delete</button>"),
        fc("src/Refund.jsx", "function handleRefund(){axios.post('/admin/refund',{orderId,amount})}\n<button onClick={handleRefund}>Refund</button>"),
        fc("src/Transfer.jsx", "function transfer(){axios.post('/api/wallet/transfer',{amount,toUserId})}\n<button onClick={transfer}>Transfer</button>"),
    ]


def endpoint_set(result: ReadableAnalysisResult) -> set[str]:
    return {p.endpoint or "" for p in result.verification_playbooks}


def main() -> int:
    analyzer = MockConsolePocAnalyzer()

    core = analyze_console_exploitability(realistic_core_fixture(), analyzer=analyzer)
    validate_promoted_shape(core, "core")
    validate_review_shape(core, "core")
    endpoints = endpoint_set(core)

    required_core = {
        "/api/auction/{item.id}/bid": "auction bid promotes",
        "/api/user/{sessionData.userId}/wallet/charge": "wallet charge promotes",
        "/api/order/{auctionItem.orderId}/complete-payment": "order complete payment promotes",
        "/api/stripe/create-checkout-session": "Stripe checkout promotes",
        "/api/iamport/prepare": "Iamport prepare promotes",
        "/api/iamport/verify": "Iamport verify promotes",
    }
    for endpoint, label in required_core.items():
        check(f"core: {label}", endpoint in endpoints, f"endpoints={sorted(endpoints)}")

    action_expectations = {
        "/api/auction/{item.id}/bid": "click bid button",
        "/api/user/{sessionData.userId}/wallet/charge": "click point charge button",
        "/api/order/{auctionItem.orderId}/complete-payment": "click payment button",
        "/api/stripe/create-checkout-session": "click payment button",
        "/api/iamport/prepare": "click payment approval button",
        "/api/iamport/verify": "click payment approval button",
    }
    for endpoint, expected in action_expectations.items():
        pb = find_playbook(core, endpoint)
        check(f"core: {endpoint} action inference", pb is not None and pb.user_action_hint == expected, f"got={pb.user_action_hint if pb else None}")

    noise_reviews = [
        rc for rc in core.review_candidates
        if any(token in "\n".join(ev.data_flow).lower() for ev in rc.evidence for token in ("session", "init", "search", "recommend"))
    ]
    check("core: session/init/search/recommend noise does not flood reviews", len(noise_reviews) <= 2, f"noise_reviews={len(noise_reviews)}")
    check("core: destructive DELETE/refund endpoints not promoted", not any("refund" in ep.lower() or "delete" in ep.lower() or "/api/user/1" in ep for ep in endpoints), f"endpoints={sorted(endpoints)}")

    helper_text = all_review_text(core)
    if core.common_console_helper is None:
        check("core: no global helper required before playbooks", True)
    else:
        check("core: helper wording separated from playbooks", "optional" in helper_text.lower() or "review candidate" in helper_text.lower())

    recovery = analyze_console_exploitability(recovery_login_fixture(), analyzer=analyzer)
    validate_promoted_shape(recovery, "recovery_login")
    recovery_endpoints = endpoint_set(recovery)
    for endpoint in ("/send-verification", "/verify-code", "/login"):
        check(f"recovery_login: {endpoint} promotes", endpoint in recovery_endpoints, f"endpoints={sorted(recovery_endpoints)}")

    route_params = analyze_console_exploitability(route_param_fixture(), analyzer=analyzer)
    validate_promoted_shape(route_params, "route_params")
    route_expectations = {
        "/api/auction/{item.id}/bid": "REPLACE_WITH_TEST_ID",
        "/api/users/{userId}/role": "REPLACE_WITH_USER_ID",
        "/api/users/{currentUserId}/profile": "REPLACE_WITH_USER_ID",
        "/api/user/{sessionData.userId}/wallet/charge": "REPLACE_WITH_USER_ID",
        "/api/order/{auctionItem.orderId}/complete-payment": "REPLACE_WITH_ORDER_ID",
        "/api/order/{orderId}/complete-payment": "REPLACE_WITH_ORDER_ID",
        "/api/products/{productId}/purchase": "REPLACE_WITH_TEST_ID",
    }
    for endpoint, const_label in route_expectations.items():
        pb = find_playbook(route_params, endpoint)
        code = pb.console_code if pb else ""
        check(f"route_params: {endpoint} promotes", pb is not None, f"endpoints={sorted(endpoint_set(route_params))}")
        check(f"route_params: {endpoint} uses editable constant", const_label in (code or ""), code or "missing playbook")
        check(f"route_params: {endpoint} not fatal placeholder", not any(endpoint in (rc.poc_generation_reason or "") for rc in route_params.review_candidates))

    destructive = analyze_console_exploitability(destructive_fixture(), analyzer=analyzer)
    destructive_endpoints = endpoint_set(destructive)
    check("destructive: no destructive playbooks promoted", not destructive_endpoints, f"endpoints={sorted(destructive_endpoints)}")
    for rc in destructive.review_candidates:
        code = (rc.console_poc.code or "") if rc.console_poc else ""
        obs_code = (rc.observational_poc.code or "") if rc.observational_poc else ""
        check("destructive: review candidate has no replay code", "fetch(" not in code + obs_code, rc.title)

    promoted_count = len(core.verification_playbooks) + len(recovery.verification_playbooks) + len(route_params.verification_playbooks) + len(destructive.verification_playbooks)
    review_count = len(core.review_candidates) + len(recovery.review_candidates) + len(route_params.review_candidates) + len(destructive.review_candidates)
    raw_count = sum(1 for result in (core, recovery, route_params, destructive) for finding in result.findings if finding.status == "raw_signal")
    helper_global = any(result.common_console_helper for result in (core, recovery, route_params, destructive))
    print("")
    print("realistic_output_summary:")
    print(f"  promoted_count={promoted_count}")
    print(f"  review_candidate_count={review_count}")
    print(f"  raw_signal_count={raw_count}")
    print(f"  common_helper_global={helper_global}")
    print(f"  core_endpoints={sorted(endpoint_set(core))}")
    print(f"  recovery_endpoints={sorted(endpoint_set(recovery))}")
    print(f"  route_param_endpoints={sorted(endpoint_set(route_params))}")
    print(f"  destructive_endpoints={sorted(endpoint_set(destructive))}")
    print("")
    print(f"verify_realistic_output: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
