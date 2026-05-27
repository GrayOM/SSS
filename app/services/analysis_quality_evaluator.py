from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Any


@dataclass
class AnalysisQualityReport:
    passed: bool
    score: int
    failures: list[str]
    warnings: list[str]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _norm(x: Any) -> str:
    return str(x or '').lower()


def _is_session_endpoint(endpoint: str, method: str) -> bool:
    e = _norm(endpoint).split('?', 1)[0].rstrip('/')
    return _norm(method) == 'get' and (
        e.endswith('/api/user/session') or e in {'/api/auth/me', '/api/me', '/api/profile/me'}
    )


def evaluate_analysis_quality(analysis_result: dict[str, Any], expectation: dict[str, Any]) -> AnalysisQualityReport:
    ra = (analysis_result or {}).get('readable_analysis', {})
    playbooks = ra.get('verification_playbooks') or []
    review = ra.get('review_candidates') or []
    executive = ra.get('executive_findings') or []
    pu = ra.get('project_understanding') or {}
    api_inv = pu.get('api_inventory') or []
    ui_events = pu.get('ui_events') or []
    flows = pu.get('business_flows') or []

    generic_action_count = sum(1 for p in playbooks if p.get('user_action_hint') == '대상 기능 버튼 클릭')
    generic_page_count = sum(1 for p in playbooks if p.get('page_hint') == '해당 기능 화면')
    endpoint_unknown_playbook_count = sum(1 for p in playbooks if _norm(p.get('endpoint')) in {'', 'unknown'})
    missing_console_code_playbook_count = sum(1 for p in playbooks if not p.get('console_code'))
    session_get_playbook_count = sum(1 for p in playbooks if _is_session_endpoint(p.get('endpoint', ''), p.get('method', 'GET')))
    compressed_library_playbook_count = sum(1 for p in playbooks if 'compressed' in _norm(' '.join(p.get('limitations') or [])))
    api_ui_linked_count = sum(1 for a in api_inv if a.get('ui_event_handler') or a.get('ui_event_type') or a.get('ui_event_text'))

    promoted_eps = [str(p.get('endpoint', '')) for p in playbooks]
    reviewed_eps = [str(r.get('endpoint', '')) for r in review]

    metrics = {
        'verification_playbooks_count': len(playbooks),
        'review_candidates_count': len(review),
        'executive_findings_count': len(executive),
        'generic_action_count': generic_action_count,
        'generic_page_count': generic_page_count,
        'endpoint_unknown_playbook_count': endpoint_unknown_playbook_count,
        'missing_console_code_playbook_count': missing_console_code_playbook_count,
        'session_get_playbook_count': session_get_playbook_count,
        'compressed_library_playbook_count': compressed_library_playbook_count,
        'api_inventory_count': len(api_inv),
        'ui_event_count': len(ui_events),
        'api_ui_linked_count': api_ui_linked_count,
        'business_flow_count': len(flows),
        'promoted_endpoint_patterns': promoted_eps,
        'reviewed_endpoint_patterns': reviewed_eps,
    }

    failures: list[str] = []
    warnings: list[str] = []

    min_pb = expectation.get('min_verification_playbooks', 0)
    max_pb = expectation.get('max_verification_playbooks', 999999)
    if len(playbooks) < min_pb:
        failures.append(f'expected at least {min_pb} verification playbooks, got {len(playbooks)}')
    if len(playbooks) > max_pb:
        failures.append(f'expected at most {max_pb} verification playbooks, got {len(playbooks)}')

    if endpoint_unknown_playbook_count > 0:
        failures.append('endpoint UNKNOWN found in verification_playbooks')
    if missing_console_code_playbook_count > 0:
        failures.append('missing console_code in verification_playbooks')
    if session_get_playbook_count > 0:
        failures.append('session/auth/me/profile GET promoted to verification_playbooks')
    if compressed_library_playbook_count > 0:
        failures.append('compressed/library evidence promoted to verification_playbooks')

    generic_action_rate = (generic_action_count / len(playbooks)) if playbooks else 0.0
    generic_page_rate = (generic_page_count / len(playbooks)) if playbooks else 0.0
    if generic_action_rate > expectation.get('max_generic_action_rate', 1.0):
        failures.append(f'generic action rate high: {generic_action_rate:.2f}')
    if generic_page_rate > expectation.get('max_generic_page_rate', expectation.get('max_generic_action_rate', 1.0)):
        failures.append(f'generic page rate high: {generic_page_rate:.2f}')

    must_review = expectation.get('must_review_endpoint_patterns') or []
    for pat in must_review:
        rp = re.compile(re.escape(pat), re.IGNORECASE)
        if any(rp.search(_norm(ep)) for ep in promoted_eps):
            failures.append(f'must_review pattern promoted: {pat}')

    should_promote = expectation.get('should_promote_endpoint_patterns') or []
    not_promoted = []
    for pat in should_promote:
        rp = re.compile(re.escape(pat), re.IGNORECASE)
        if not any(rp.search(_norm(ep)) for ep in promoted_eps):
            not_promoted.append(pat)
    if should_promote and not_promoted:
        failures.append(f'should_promote_endpoint_patterns not promoted: {", ".join(not_promoted)}')

    req = expectation.get('required_project_understanding') or {}
    if req.get('framework') and _norm(pu.get('framework')) != _norm(req.get('framework')):
        failures.append(f"framework mismatch: expected {req.get('framework')}, got {pu.get('framework')}")
    if len(api_inv) < int(req.get('min_api_inventory', 0)):
        failures.append(f"api_inventory too small: {len(api_inv)} < {req.get('min_api_inventory')}")
    if len(flows) < int(req.get('min_business_flows', 0)):
        failures.append(f"business_flows too small: {len(flows)} < {req.get('min_business_flows')}")

    score = max(0, 100 - 15 * len(failures) - 3 * len(warnings))
    return AnalysisQualityReport(passed=not failures, score=score, failures=failures, warnings=warnings, metrics=metrics)
