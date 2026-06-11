#!/usr/bin/env python3
"""Generalization verifier for SSS public-pattern fixtures.

Runs derived, minimal source fixtures through the real readable analysis
pipeline and checks product-shape invariants for broader frontend patterns.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.schemas import FileContent, ReadableAnalysisResult
from app.services.console_poc_analysis_service import MockConsolePocAnalyzer, analyze_console_exploitability


PASS = 0
FAIL = 0

FORBIDDEN_PROMOTED = (
    "window.SSS_POC",
    "window.SSS_REVIEW_POC",
    "common_console_helper",
    "armMutation",
    "capture/replay",
    "install helper",
)


def fc(path: str, content: str) -> FileContent:
    ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return FileContent(path=path, extension=ext, size=len(content), priority=1, reason_code="INCLUDED", content_hash="generalization", content=content)


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        print(f"PASS  {name}")
        PASS += 1
    else:
        print(f"FAIL  {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


def playbook(result: ReadableAnalysisResult, endpoint: str):
    return next((p for p in result.verification_playbooks if p.endpoint == endpoint), None)


def review_for(result: ReadableAnalysisResult, endpoint: str):
    for f in result.review_candidates:
        flows = "\n".join(x for ev in f.evidence for x in ev.data_flow)
        if endpoint in flows:
            return f
    return None


def validate_promoted(result: ReadableAnalysisResult, label: str) -> None:
    check(f"{label}: no global common helper", result.common_console_helper is None)
    for pb in result.verification_playbooks:
        target = f"{pb.method} {pb.endpoint}"
        code = pb.console_code or ""
        check(f"{label}: {target} has console code", bool(code.strip()))
        check(f"{label}: {target} direct proof code", "fetch(" in code or "location." in code or "Storage.setItem" in code)
        forbidden = [x for x in FORBIDDEN_PROMOTED if x in code]
        check(f"{label}: {target} helper-free", not forbidden, str(forbidden))
        if pb.method in {"POST", "PUT", "PATCH"}:
            check(f"{label}: {target} confirm guard", "confirm(" in code)
        non_empty = [line for line in code.splitlines() if line.strip()]
        is_legacy_form_replay = "Legacy Form Replay" in (pb.risk_type or "")
        check(f"{label}: {target} short code", is_legacy_form_replay or len(non_empty) <= 12, f"lines={len(non_empty)}")
        proof = "\n".join((pb.proof_steps or []) + (pb.success_criteria or []) + (pb.evidence_to_capture or []))
        check(f"{label}: {target} proof has no helper wording", not any(x in proof for x in FORBIDDEN_PROMOTED), proof)
        check(f"{label}: {target} source location", bool(pb.source_path) and isinstance(pb.start_line, int))


def public_pattern_fixture() -> list[FileContent]:
    return [
        fc(
            "src/AngularPayment.ts",
            """
export class PaymentComponent {
  amount = 1
  orderId = 'order-1'
  private readonly host = environment.host + '/api/payment'
  submitPayment() {
    return this.http.post(`${this.host}/${this.orderId}/complete`, { amount: this.amount, orderId: this.orderId })
  }
}
<button (click)="submitPayment()">Pay now</button>
""",
        ),
        fc(
            "templates/profile.html",
            """
<form method="POST" action="/profile">
  <input name="userId">
  <input name="displayName">
  <button type="submit">Save profile</button>
</form>
""",
        ),
        fc(
            "src/WrapperClient.jsx",
            """
function RoleEditor({ userId }) {
  function saveRole() {
    api.patch(`/api/users/${userId}/role`, { role, userId });
  }
  return <button onClick={saveRole}>Save role</button>;
}
""",
        ),
        fc(
            "src/FormDataUpload.js",
            """
function submitEvidence() {
  const fd = new FormData();
  fd.append('amount', amount);
  fd.append('paymentId', paymentId);
  return fetch('/api/payments/evidence', { method: 'POST', body: fd });
}
document.querySelector('#upload').addEventListener('submit', submitEvidence);
""",
        ),
        fc(
            "src/SearchNoise.js",
            """
const params = new URLSearchParams();
params.append('keyword', keyword);
params.append('page', page);
fetch('/api/search?' + params.toString());
fetch('/api/user/session');
fetch('/session/init');
""",
        ),
        fc(
            "src/DomXss.js",
            """
window.addEventListener('message', function (event) {
  document.getElementById('preview').innerHTML = event.data;
});
const q = location.search;
document.getElementById('searchValue').innerHTML = q;
""",
        ),
        fc(
            "src/AuthBranch.js",
            """
const user = JSON.parse(sessionStorage.getItem('user') || '{}');
if (user.role === 'admin') {
  navigate('/admin');
  document.querySelector('#admin').style.display = 'block';
}
""",
        ),
        fc(
            "src/Danger.js",
            """
function refund() { fetch('/admin/refund', { method: 'POST', body: JSON.stringify({ orderId, amount }) }); }
function removeUser() { fetch('/api/users/1', { method: 'DELETE' }); }
<button onClick={refund}>Refund</button>
<button onClick={removeUser}>Delete</button>
""",
        ),
    ]


def main() -> int:
    result = analyze_console_exploitability(public_pattern_fixture(), analyzer=MockConsolePocAnalyzer())
    validate_promoted(result, "generalization")

    expected_promoted = {
        "/api/payment/{this.orderId}/complete": "Angular HttpClient alias route param promotes",
        "/api/users/{userId}/role": "generic api wrapper patch route param promotes",
        "/api/payments/evidence": "FormData mutation promotes",
    }
    for endpoint, label in expected_promoted.items():
        pb = playbook(result, endpoint)
        check(label, pb is not None, f"endpoints={[p.endpoint for p in result.verification_playbooks]}")
        if pb:
            check(f"{endpoint}: route constants when needed", ("REPLACE_WITH_" in (pb.console_code or "")) if "{" in endpoint else True, pb.console_code or "")

    form_review = review_for(result, "/profile") or playbook(result, "/profile")
    check("HTML form action is extracted into output", form_review is not None)
    if review_for(result, "/profile"):
        rc = review_for(result, "/profile")
        check("HTML form review is not overconfident", rc.status == "review_candidate" and rc.poc_generation_status == "manual_plan")

    noisy_reviews = [
        f for f in result.review_candidates
        if any(token in "\n".join(ev.data_flow).lower() for ev in f.evidence for token in ("session", "init", "search", "recommend"))
    ]
    check("session/search/init noise is limited", len(noisy_reviews) <= 2, f"noise_reviews={len(noisy_reviews)}")

    destructive = [p for p in result.verification_playbooks if p.method == "DELETE" or any(x in (p.endpoint or "").lower() for x in ("refund", "transfer", "withdraw", "bulk", "remove", "delete"))]
    check("destructive endpoints not promoted", not destructive, str([(p.method, p.endpoint) for p in destructive]))

    dom_promoted = [p for p in result.verification_playbooks if p.method == "DOM"]
    check("DOM source/sink candidates promote", bool(dom_promoted), f"playbooks={[p.endpoint for p in result.verification_playbooks]}")
    storage_promoted = [p for p in result.verification_playbooks if "Storage.setItem" in (p.console_code or "")]
    check("storage/auth branch candidate promotes", bool(storage_promoted))

    review_manual = all(rc.status in {"review_candidate", "raw_signal"} and rc.poc_generation_status != "executable" for rc in result.review_candidates)
    check("review candidates stay non-confirmed", review_manual)

    print("")
    print("generalization_summary:")
    print(f"  promoted_count={len(result.verification_playbooks)}")
    print(f"  review_candidate_count={len(result.review_candidates)}")
    print(f"  raw_signal_count={sum(1 for f in result.findings if f.status == 'raw_signal')}")
    print(f"  common_helper_global={bool(result.common_console_helper)}")
    print(f"  promoted_endpoints={sorted(p.endpoint or '' for p in result.verification_playbooks)}")
    print("")
    print(f"verify_generalization: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
