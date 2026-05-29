import copy
import json
from pathlib import Path

from app.services.analysis_quality_evaluator import evaluate_analysis_quality

ROOT = Path(__file__).parent / 'fixtures'


def _load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _base():
    return _load('analysis_results/pass_base_result.json')


def test_nls_recommend_review_passes_real_shape():
    r = evaluate_analysis_quality(_load('analysis_results/nls_real_shape_result.json'), _load('expectations/sample_jquery_search_expectation.json'))
    assert r.passed


def test_nls_recommend_promoted_fails_real_shape():
    data = _load('analysis_results/nls_real_shape_result.json')
    data['readable_analysis']['verification_playbooks'] = [{
        "risk_type": "Generic API Review Candidate",
        "evidence": [{"data_flow": ["method: GET", "endpoint: /header/recommend_search.do"]}],
        "console_code": "x",
        "user_action_hint": "대상 기능 버튼 클릭",
        "page_hint": "해당 기능 화면"
    }]
    r = evaluate_analysis_quality(data, _load('expectations/sample_jquery_search_expectation.json'))
    assert not r.passed
    assert any('must_review pattern promoted' in x for x in r.failures)


def test_ebs_zero_playbooks_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'] = []
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('expected at least' in x for x in r.failures)


def test_unknown_endpoint_playbook_fails_with_reason():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = 'UNKNOWN'
    data['readable_analysis']['verification_playbooks'][0]['data_flow']['api_call_or_sink'] = 'UNKNOWN'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('endpoint UNKNOWN' in x for x in r.failures)


def test_promoted_source_path_unknown_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['source_path'] = 'UNKNOWN'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('promoted_without_source_location' in x for x in r.failures)


def test_promoted_fallback_location_without_evidence_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['source_path'] = 'src/fallback.js'
    data['readable_analysis']['verification_playbooks'][0]['start_line'] = 1
    data['readable_analysis']['verification_playbooks'][0]['end_line'] = 1
    data['readable_analysis']['findings'] = []
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('promoted_without_evidence_backed_source_location' in x for x in r.failures)


def test_valid_evidence_backed_source_location_passes():
    r = evaluate_analysis_quality(_base(), _load('expectations/sample_jquery_template_large_expectation.json'))
    assert r.passed


def test_get_unknown_promoted_playbook_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    pb = data['readable_analysis']['verification_playbooks'][0]
    pb['method'] = 'GET'
    pb['endpoint'] = 'GET UNKNOWN'
    pb['data_flow']['api_call_or_sink'] = 'GET UNKNOWN'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('endpoint UNKNOWN' in x for x in r.failures)


def test_real_api_endpoint_promoted_playbook_passes():
    r = evaluate_analysis_quality(_base(), _load('expectations/sample_jquery_template_large_expectation.json'))
    assert r.passed


def test_generic_fetch_target_without_endpoint_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    pb = data['readable_analysis']['verification_playbooks'][0]
    pb['endpoint'] = ''
    pb['data_flow']['api_call_or_sink'] = 'fetch'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('promoted_without_endpoint_or_sink' in x for x in r.failures)


def test_generic_ajax_target_without_endpoint_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    pb = data['readable_analysis']['verification_playbooks'][0]
    pb['endpoint'] = ''
    pb['data_flow']['api_call_or_sink'] = '$.ajax'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('promoted_without_endpoint_or_sink' in x for x in r.failures)


def test_dom_sink_requires_source_to_sink_evidence():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    pb = data['readable_analysis']['verification_playbooks'][0]
    pb.update({
        'source_path': 'src/dom.js',
        'start_line': 5,
        'end_line': 8,
        'method': 'DOM',
        'endpoint': '',
        'function_name': 'renderProfile',
        'root_cause': 'unsafe DOM assignment',
        'why_exploitable': 'attacker-controlled input reaches innerHTML',
        'data_flow': {
            'user_action': 'open crafted URL',
            'handler': 'renderProfile',
            'api_call_or_sink': 'innerHTML',
            'missing_guard_or_validation': 'no sanitizer',
        },
        'breakpoint_plan': {
            'file': 'src/dom.js',
            'line': 7,
            'function': 'renderProfile',
            'when_to_pause': 'before DOM assignment',
            'what_variable_or_request_to_check': 'input value before innerHTML',
        },
    })
    data['readable_analysis']['findings'] = [{
        'id': 'pb1',
        'evidence': [{
            'source_path': 'src/dom.js',
            'start_line': 5,
            'end_line': 8,
            'snippet': 'input is assigned to innerHTML',
            'reason': 'sink is present',
            'data_flow': ['sink: innerHTML'],
        }],
    }]
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('promoted_without_endpoint_or_sink' in x for x in r.failures)

    data['readable_analysis']['findings'][0]['evidence'][0]['data_flow'].insert(0, 'source -> state/storage -> sink')
    r = evaluate_analysis_quality(data, exp)
    assert r.passed


def test_dom_sink_with_source_to_sink_evidence_passes():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    pb = data['readable_analysis']['verification_playbooks'][0]
    pb.update({
        'source_path': 'src/dom.js',
        'start_line': 5,
        'end_line': 8,
        'method': 'DOM',
        'endpoint': '',
        'function_name': 'renderProfile',
        'root_cause': 'unsafe DOM assignment',
        'why_exploitable': 'attacker-controlled input reaches innerHTML',
        'data_flow': {
            'user_action': 'open crafted URL',
            'handler': 'renderProfile',
            'api_call_or_sink': 'innerHTML',
            'missing_guard_or_validation': 'no sanitizer',
        },
        'breakpoint_plan': {
            'file': 'src/dom.js',
            'line': 7,
            'function': 'renderProfile',
            'when_to_pause': 'before DOM assignment',
            'what_variable_or_request_to_check': 'input value before innerHTML',
        },
    })
    data['readable_analysis']['findings'] = [{
        'id': 'pb1',
        'evidence': [{
            'source_path': 'src/dom.js',
            'start_line': 5,
            'end_line': 8,
            'snippet': 'input is assigned to innerHTML',
            'reason': 'source-to-sink flow reaches innerHTML',
            'data_flow': ['source -> state/storage -> sink', 'sink: innerHTML'],
        }],
    }]
    r = evaluate_analysis_quality(data, exp)
    assert r.passed


def test_missing_console_code_playbook_fails_with_reason():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['console_code'] = None
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('missing console_code' in x for x in r.failures)


def test_generic_action_rate_exceeded_fails_with_reason():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['user_action_hint'] = '대상 기능 버튼 클릭'
    data['readable_analysis']['verification_playbooks'][0]['page_hint'] = '해당 기능 화면'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('generic action rate' in x for x in r.failures)


def test_must_not_promote_generic_api_review_fails():
    data = _base()
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['risk_type'] = 'Generic API Review Candidate'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('must_not_promote violated: generic_api_review' in x for x in r.failures)


def test_should_promote_any_min_count_warning_when_not_strict():
    data = _base()
    exp = copy.deepcopy(_load('expectations/sample_jquery_template_large_expectation.json'))
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = '/api/none'
    r = evaluate_analysis_quality(data, exp)
    assert r.passed
    assert any('should_promote_any matches too low' in x for x in r.warnings)


def test_should_promote_any_min_count_failure_when_strict():
    data = _base()
    exp = copy.deepcopy(_load('expectations/sample_jquery_template_large_expectation.json'))
    exp['strict'] = True
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = '/api/none'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('should_promote_any matches too low' in x for x in r.failures)


def test_promoted_without_console_code_fail_gate():
    data = _base()
    exp = copy.deepcopy(_load('expectations/sample_jquery_template_large_expectation.json'))
    data['readable_analysis']['verification_playbooks'][0]['console_code'] = None
    r = evaluate_analysis_quality(data, exp)
    assert any('promoted_without_console_code' in x or 'missing console_code' in x for x in r.failures)


def test_promoted_without_breakpoint_plan_fail_gate():
    data = _base()
    exp = copy.deepcopy(_load('expectations/sample_jquery_template_large_expectation.json'))
    data['readable_analysis']['verification_playbooks'][0].pop('breakpoint_plan', None)
    r = evaluate_analysis_quality(data, exp)
    assert any('promoted_without_breakpoint_plan' in x for x in r.failures)


def test_poc_generation_rate_threshold_fail():
    data = _base()
    exp = copy.deepcopy(_load('expectations/sample_jquery_template_large_expectation.json'))
    data['readable_analysis']['review_candidates'] = [{"severity": "medium"}]
    r = evaluate_analysis_quality(data, exp)
    assert any('poc_generation_rate below threshold' in x for x in r.failures)
