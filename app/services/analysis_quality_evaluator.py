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


def _extract_from_data_flow(item: dict[str, Any], key: str) -> str:
    for ev in item.get('evidence') or []:
        for df in ev.get('data_flow') or []:
            if isinstance(df, str) and df.lower().startswith(f'{key}:'):
                return df.split(':', 1)[1].strip()
    return ''


def _extract_endpoint(item: dict[str, Any]) -> str:
    return (
        item.get('endpoint')
        or _extract_from_data_flow(item, 'endpoint')
        or item.get('verification_playbook', {}).get('endpoint')
        or ''
    )


def _extract_method(item: dict[str, Any]) -> str:
    return (
        item.get('method')
        or _extract_from_data_flow(item, 'method')
        or item.get('verification_playbook', {}).get('method')
        or ''
    )


def _extract_risk_type(item: dict[str, Any]) -> str:
    return str(item.get('risk_type') or item.get('vulnerability_type') or '')


def _is_session_endpoint(endpoint: str, method: str) -> bool:
    e = _norm(endpoint).split('?', 1)[0].rstrip('/')
    return _norm(method) == 'get' and (e.endswith('/api/user/session') or e in {'/api/auth/me', '/api/me', '/api/profile/me'})


def _is_search_recommend(endpoint: str, method: str) -> bool:
    e = _norm(endpoint)
    return _norm(method) == 'get' and any(k in e for k in ('search', 'recommend'))


def evaluate_analysis_quality(analysis_result: dict[str, Any], expectation: dict[str, Any]) -> AnalysisQualityReport:
    strict = bool(expectation.get('strict', False))
    ra = (analysis_result or {}).get('readable_analysis', {})
    playbooks = ra.get('verification_playbooks') or []
    review = ra.get('review_candidates') or []
    executive = ra.get('executive_findings') or []
    pu = ra.get('project_understanding') or {}
    api_inv = pu.get('api_inventory') or []
    ui_events = pu.get('ui_events') or []
    flows = pu.get('business_flows') or []

    pb_endpoints = [_extract_endpoint(p) for p in playbooks]
    pb_methods = [_extract_method(p) for p in playbooks]
    rv_endpoints = [_extract_endpoint(r) for r in review]

    generic_action_count = sum(1 for p in playbooks if p.get('user_action_hint') == '대상 기능 버튼 클릭')
    generic_page_count = sum(1 for p in playbooks if p.get('page_hint') == '해당 기능 화면')
    endpoint_unknown_playbook_count = sum(1 for e in pb_endpoints if _norm(e) in {'', 'unknown'})
    missing_console_code_playbook_count = sum(1 for p in playbooks if not p.get('console_code'))
    session_get_playbook_count = sum(1 for e, m in zip(pb_endpoints, pb_methods) if _is_session_endpoint(e, m))
    compressed_library_playbook_count = sum(1 for p in playbooks if 'compressed' in _norm(' '.join(p.get('limitations') or []) + ' ' + ' '.join(p.get('verification_notes') or [])))
    api_ui_linked_count = sum(1 for a in api_inv if a.get('ui_event_handler') or a.get('ui_event_type') or a.get('ui_event_text'))

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
        'promoted_endpoint_patterns': pb_endpoints,
        'reviewed_endpoint_patterns': rv_endpoints,
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

    generic_action_rate = (generic_action_count / len(playbooks)) if playbooks else 0.0
    generic_page_rate = (generic_page_count / len(playbooks)) if playbooks else 0.0
    if generic_action_rate > expectation.get('max_generic_action_rate', 1.0):
        failures.append(f'generic action rate high: {generic_action_rate:.2f}')
    if generic_page_rate > expectation.get('max_generic_page_rate', expectation.get('max_generic_action_rate', 1.0)):
        failures.append(f'generic page rate high: {generic_page_rate:.2f}')

    must_not = set(expectation.get('must_not_promote') or [])
    for p in playbooks:
        ep = _extract_endpoint(p)
        mt = _extract_method(p)
        rt = _norm(_extract_risk_type(p))
        notes = _norm(' '.join(p.get('limitations') or []) + ' ' + ' '.join(p.get('verification_notes') or []))
        if 'session_check' in must_not and _is_session_endpoint(ep, mt):
            failures.append('must_not_promote violated: session_check')
        if 'search_recommend_get' in must_not and _is_search_recommend(ep, mt):
            failures.append('must_not_promote violated: search_recommend_get')
        if 'compressed_library' in must_not and ('compressed' in notes or 'library' in notes):
            failures.append('must_not_promote violated: compressed_library')
        if 'generic_api_review' in must_not and 'generic api review candidate' in rt:
            failures.append('must_not_promote violated: generic_api_review')
        if 'read_only_get' in must_not and _norm(mt) == 'get':
            failures.append('must_not_promote violated: read_only_get')

    must_review = expectation.get('must_review_endpoint_patterns') or []
    for pat in must_review:
        rp = re.compile(re.escape(pat), re.IGNORECASE)
        if any(rp.search(_norm(ep)) for ep in pb_endpoints):
            failures.append(f'must_review pattern promoted: {pat}')

    should_promote = expectation.get('should_promote_endpoint_patterns') or []
    not_promoted = [pat for pat in should_promote if not any(re.search(re.escape(pat), _norm(ep), re.I) for ep in pb_endpoints)]
    if should_promote and not_promoted:
        failures.append(f'should_promote_endpoint_patterns not promoted: {", ".join(not_promoted)}')

    any_patterns = expectation.get('should_promote_any_endpoint_patterns') or []
    min_matches = int(expectation.get('min_should_promote_matches', 0))
    if any_patterns:
        matches = sum(1 for pat in any_patterns if any(re.search(re.escape(pat), _norm(ep), re.I) for ep in pb_endpoints))
        if matches < min_matches:
            msg = f'should_promote_any matches too low: {matches} < {min_matches}'
            (failures if strict else warnings).append(msg)

    req = expectation.get('required_project_understanding') or {}
    if req.get('framework') and _norm(pu.get('framework')) != _norm(req.get('framework')):
        failures.append(f"framework mismatch: expected {req.get('framework')}, got {pu.get('framework')}")
    if len(api_inv) < int(req.get('min_api_inventory', 0)):
        failures.append(f"api_inventory too small: {len(api_inv)} < {req.get('min_api_inventory')}")
    if len(flows) < int(req.get('min_business_flows', 0)):
        failures.append(f"business_flows too small: {len(flows)} < {req.get('min_business_flows')}")

    if len(api_inv) >= 5 and api_ui_linked_count <= 1:
        (failures if strict else warnings).append('api_ui_linked_count is low')
    if len(ui_events) == 0 and len(api_inv) >= 5:
        (failures if strict else warnings).append('ui_event_count is 0 while api_inventory_count is high')
    if len(review) > (len(playbooks) * 10 + 20):
        (failures if strict else warnings).append('review_candidates_count is disproportionately high')

    score = max(0, 100 - 15 * len(failures) - 3 * len(warnings))
    return AnalysisQualityReport(passed=not failures, score=score, failures=sorted(set(failures)), warnings=sorted(set(warnings)), metrics=metrics)
