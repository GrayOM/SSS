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


def _compact(x: Any) -> str:
    return ' '.join(str(x or '').strip().lower().split())


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


def _extract_data_flow_object_value(item: dict[str, Any], key: str) -> str:
    flow = item.get('data_flow') or {}
    if isinstance(flow, dict):
        return str(flow.get(key) or '').strip()
    return ''


def _extract_sink(item: dict[str, Any]) -> str:
    endpoint = str(_extract_endpoint(item) or '').strip()
    if endpoint.lower().startswith('dom sink:'):
        return endpoint.split(':', 1)[1].strip()
    return (
        item.get('sink')
        or _extract_from_data_flow(item, 'sink')
        or _extract_data_flow_object_value(item, 'api_call_or_sink')
        or ''
    )


def _extract_risk_type(item: dict[str, Any]) -> str:
    return str(item.get('risk_type') or item.get('vulnerability_type') or '')


def _has_source_location(item: dict[str, Any]) -> bool:
    source_path = _compact(item.get('source_path'))
    start_line = item.get('start_line')
    end_line = item.get('end_line')
    return (
        source_path not in {'', 'unknown'}
        and type(start_line) is int
        and start_line > 0
        and type(end_line) is int
        and end_line >= start_line
    )


def _evidence_for_item(item: dict[str, Any], findings_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    evidence = item.get('evidence')
    if isinstance(evidence, list) and evidence:
        return [ev for ev in evidence if isinstance(ev, dict)]
    item_id = str(item.get('id') or '')
    matched = findings_by_id.get(item_id) if item_id else None
    matched_evidence = matched.get('evidence') if matched else None
    if isinstance(matched_evidence, list):
        return [ev for ev in matched_evidence if isinstance(ev, dict)]
    return []


def _has_evidence_backed_source_location(item: dict[str, Any], evidence: list[dict[str, Any]]) -> bool:
    if not _has_source_location(item):
        return False
    source_path = str(item.get('source_path') or '').strip()
    start_line = item.get('start_line')
    end_line = item.get('end_line')
    for ev in evidence:
        if _compact(ev.get('source_path')) != _compact(source_path):
            continue
        ev_start = ev.get('start_line')
        ev_end = ev.get('end_line')
        if type(ev_start) is not int or ev_start <= 0:
            continue
        if type(ev_end) is not int or ev_end < ev_start:
            continue
        overlaps = ev_start <= end_line and ev_end >= start_line
        has_evidence_body = bool(str(ev.get('snippet') or ev.get('reason') or '').strip() or ev.get('data_flow'))
        if overlaps and has_evidence_body:
            return True
    return False


def _has_breakpoint_plan(item: dict[str, Any]) -> bool:
    plan = item.get('breakpoint_plan') or {}
    return bool(plan.get('file')) and isinstance(plan.get('line'), int) and bool(plan.get('when_to_pause')) and bool(plan.get('what_variable_or_request_to_check'))


def _has_poc_injection_plan(item: dict[str, Any]) -> bool:
    plan = item.get('poc_injection_plan') or {}
    return bool(plan.get('where_to_paste_code')) and bool(plan.get('when_to_run')) and bool(plan.get('required_user_action'))


def _has_why_exploitable(item: dict[str, Any]) -> bool:
    return bool(str(item.get('why_exploitable') or '').strip())


def _is_unknown_endpoint(endpoint: str) -> bool:
    value = _compact(endpoint)
    if value in {'', 'unknown', 'unknown endpoint'}:
        return True
    if value.startswith('unknown endpoint'):
        return True
    return bool(re.fullmatch(r'(get|post|put|patch|delete|head|options)\s+unknown', value))


GENERIC_TRANSPORT_TARGETS = {
    'fetch',
    '$.ajax',
    'ajax',
    'axios',
    'xmlhttprequest',
    'xhr',
    'function_call',
    'request',
    'client',
    'httpclient',
}


def _target_without_method(value: str) -> str:
    return re.sub(r'^(get|post|put|patch|delete|head|options)\s+', '', str(value or '').strip(), flags=re.I)


def _is_generic_transport_target(value: str) -> bool:
    stripped = _target_without_method(value)
    normalized = _compact(stripped).replace(' ', '')
    return normalized in GENERIC_TRANSPORT_TARGETS


def _is_real_endpoint_path(value: str) -> bool:
    target = _target_without_method(value)
    if _is_unknown_endpoint(target) or _is_generic_transport_target(target):
        return False
    if target.lower().startswith('dom sink:'):
        return False
    return bool(re.match(r'^(https?://|/|\{?[A-Za-z_][A-Za-z0-9_.]*\}?/)', target))


def _dangerous_dom_sink(sink: str) -> str:
    value = _compact(sink).replace('dom sink:', '').strip()
    aliases = {
        'innerhtml': 'innerhtml',
        '.innerhtml': 'innerhtml',
        'document.write': 'document.write',
        'document.write()': 'document.write',
        'eval': 'eval',
        'eval()': 'eval',
    }
    return aliases.get(value, '')


def _has_source_to_sink_evidence(evidence: list[dict[str, Any]], sink: str) -> bool:
    sink_key = _dangerous_dom_sink(sink)
    if not sink_key:
        return False
    for ev in evidence:
        flows = [str(x).lower() for x in (ev.get('data_flow') or []) if isinstance(x, str)]
        joined = ' '.join(flows + [str(ev.get('reason') or '').lower()])
        has_source_sink_flow = (
            ('source' in joined and 'sink' in joined)
            or 'source-to-sink' in joined
            or 'source ->' in joined
        )
        has_sink = sink_key in joined or sink_key in str(ev.get('snippet') or '').lower()
        if has_source_sink_flow and has_sink:
            return True
    return False


def _has_api_call_or_sink(item: dict[str, Any], evidence: list[dict[str, Any]]) -> bool:
    endpoint = str(_extract_endpoint(item) or '').strip()
    api_or_sink = _extract_data_flow_object_value(item, 'api_call_or_sink')
    sink = _extract_sink(item)
    if endpoint and _is_real_endpoint_path(endpoint):
        return True
    if api_or_sink and _is_real_endpoint_path(api_or_sink):
        return True
    if _dangerous_dom_sink(sink or endpoint or api_or_sink):
        return _has_source_to_sink_evidence(evidence, sink or endpoint or api_or_sink)
    return False


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
    findings = ra.get('findings') or []
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
    findings_by_id = {str(f.get('id')): f for f in findings if isinstance(f, dict) and f.get('id')}
    playbook_evidence = [_evidence_for_item(p, findings_by_id) for p in playbooks]

    endpoint_unknown_playbook_count = sum(
        1 for p, ev in zip(playbooks, playbook_evidence)
        if _is_unknown_endpoint(_extract_endpoint(p)) and not _has_api_call_or_sink(p, ev)
    )
    missing_console_code_playbook_count = sum(1 for p in playbooks if not p.get('console_code'))
    session_get_playbook_count = sum(1 for e, m in zip(pb_endpoints, pb_methods) if _is_session_endpoint(e, m))
    compressed_library_playbook_count = sum(1 for p in playbooks if 'compressed' in _norm(' '.join(p.get('limitations') or []) + ' ' + ' '.join(p.get('verification_notes') or [])))
    api_ui_linked_count = sum(1 for a in api_inv if a.get('ui_event_handler') or a.get('ui_event_type') or a.get('ui_event_text'))
    review_observational_poc_count = sum(1 for r in review if (r.get('observational_poc') or (r.get('console_poc') and r.get('console_poc', {}).get('code'))))
    manual_poc_plan_count = sum(1 for r in review if (r.get('manual_poc_plan') or []))
    promoted_without_console_code_count = sum(1 for p in playbooks if not p.get('console_code'))
    promoted_without_breakpoint_plan_count = sum(1 for p in playbooks if not _has_breakpoint_plan(p))
    promoted_without_poc_injection_plan_count = sum(1 for p in playbooks if not _has_poc_injection_plan(p))
    promoted_without_source_location_count = sum(1 for p in playbooks if not _has_source_location(p))
    promoted_without_evidence_source_location_count = sum(1 for p, ev in zip(playbooks, playbook_evidence) if not _has_evidence_backed_source_location(p, ev))
    promoted_without_why_exploitable_count = sum(1 for p in playbooks if not _has_why_exploitable(p))
    promoted_without_target_count = sum(1 for p, ev in zip(playbooks, playbook_evidence) if not _has_api_call_or_sink(p, ev))
    promoted_manual_plan_only_count = sum(1 for p in playbooks if p.get('manual_poc_plan') and not p.get('console_code'))
    poc_generated_count = sum(1 for p in playbooks if p.get('console_code')) + review_observational_poc_count + manual_poc_plan_count
    candidates_without_any_poc_count = sum(1 for r in review if not (r.get('observational_poc') or r.get('manual_poc_plan') or (r.get('console_poc') and r.get('console_poc', {}).get('code'))))
    total_candidates = len(playbooks) + len(review)
    poc_generation_rate = (poc_generated_count / total_candidates) if total_candidates else 0.0

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
        'poc_generated_count': poc_generated_count,
        'poc_missing_count': candidates_without_any_poc_count,
        'review_observational_poc_count': review_observational_poc_count,
        'manual_poc_plan_count': manual_poc_plan_count,
        'poc_generation_rate': poc_generation_rate,
        'promoted_without_console_code_count': promoted_without_console_code_count,
        'promoted_without_breakpoint_plan_count': promoted_without_breakpoint_plan_count,
        'promoted_without_poc_injection_plan_count': promoted_without_poc_injection_plan_count,
        'promoted_without_source_location_count': promoted_without_source_location_count,
        'promoted_without_evidence_source_location_count': promoted_without_evidence_source_location_count,
        'promoted_without_why_exploitable_count': promoted_without_why_exploitable_count,
        'promoted_without_target_count': promoted_without_target_count,
        'promoted_manual_plan_only_count': promoted_manual_plan_only_count,
        'candidates_without_any_poc_count': candidates_without_any_poc_count,
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
    if expectation.get('require_poc_for_promoted', False) and promoted_without_console_code_count > 0:
        failures.append('promoted_without_console_code detected')
    if promoted_without_breakpoint_plan_count > 0:
        failures.append('promoted_without_breakpoint_plan detected')
    if promoted_without_poc_injection_plan_count > 0:
        failures.append('promoted_without_poc_injection_plan detected')
    if promoted_without_source_location_count > 0:
        failures.append('promoted_without_source_location detected')
    if promoted_without_evidence_source_location_count > 0:
        failures.append('promoted_without_evidence_backed_source_location detected')
    if promoted_without_why_exploitable_count > 0:
        failures.append('promoted_without_why_exploitable detected')
    if promoted_without_target_count > 0:
        failures.append('promoted_without_endpoint_or_sink detected')
    if promoted_manual_plan_only_count > 0:
        failures.append('manual_poc_plan promoted without console_code detected')

    generic_action_rate = (generic_action_count / len(playbooks)) if playbooks else 0.0
    generic_page_rate = (generic_page_count / len(playbooks)) if playbooks else 0.0
    if generic_action_rate > expectation.get('max_generic_action_rate', 1.0):
        failures.append(f'generic action rate high: {generic_action_rate:.2f}')
    if generic_page_rate > expectation.get('max_generic_page_rate', expectation.get('max_generic_action_rate', 1.0)):
        failures.append(f'generic page rate high: {generic_page_rate:.2f}')
    min_poc_rate = float(expectation.get('min_poc_generation_rate', 0.0))
    if poc_generation_rate < min_poc_rate:
        failures.append(f'poc_generation_rate below threshold: {poc_generation_rate:.2f} < {min_poc_rate:.2f}')
    if expectation.get('require_observational_poc_for_review', False):
        high_med_review_missing = sum(1 for r in review if _norm(r.get('severity')) in {'high', 'medium'} and not (r.get('observational_poc') or r.get('manual_poc_plan') or (r.get('console_poc') and r.get('console_poc', {}).get('code'))))
        if high_med_review_missing > 0:
            msg = f'candidates_without_any_poc high/medium reviews: {high_med_review_missing}'
            (failures if strict else warnings).append(msg)

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
