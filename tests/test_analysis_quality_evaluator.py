import copy
import json
from pathlib import Path

from app.services.analysis_quality_evaluator import evaluate_analysis_quality

ROOT = Path(__file__).parent / 'fixtures'


def _load(rel):
    return json.loads((ROOT / rel).read_text())


def _base():
    return _load('analysis_results/pass_base_result.json')


def test_nls_recommend_review_passes_real_shape():
    r = evaluate_analysis_quality(_load('analysis_results/nls_real_shape_result.json'), _load('expectations/nls_expectation.json'))
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
    r = evaluate_analysis_quality(data, _load('expectations/nls_expectation.json'))
    assert not r.passed
    assert any('must_review pattern promoted' in x for x in r.failures)


def test_ebs_zero_playbooks_fails():
    data = _base()
    exp = _load('expectations/ebs_expectation.json')
    data['readable_analysis']['verification_playbooks'] = []
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('expected at least' in x for x in r.failures)


def test_unknown_endpoint_playbook_fails_with_reason():
    data = _base()
    exp = _load('expectations/ebs_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = 'UNKNOWN'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('endpoint UNKNOWN' in x for x in r.failures)


def test_missing_console_code_playbook_fails_with_reason():
    data = _base()
    exp = _load('expectations/ebs_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['console_code'] = None
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('missing console_code' in x for x in r.failures)


def test_generic_action_rate_exceeded_fails_with_reason():
    data = _base()
    exp = _load('expectations/ebs_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['user_action_hint'] = '대상 기능 버튼 클릭'
    data['readable_analysis']['verification_playbooks'][0]['page_hint'] = '해당 기능 화면'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('generic action rate' in x for x in r.failures)


def test_must_not_promote_generic_api_review_fails():
    data = _base()
    exp = _load('expectations/ebs_expectation.json')
    data['readable_analysis']['verification_playbooks'][0]['risk_type'] = 'Generic API Review Candidate'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('must_not_promote violated: generic_api_review' in x for x in r.failures)


def test_should_promote_any_min_count_warning_when_not_strict():
    data = _base()
    exp = copy.deepcopy(_load('expectations/ebs_expectation.json'))
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = '/api/none'
    r = evaluate_analysis_quality(data, exp)
    assert r.passed
    assert any('should_promote_any matches too low' in x for x in r.warnings)


def test_should_promote_any_min_count_failure_when_strict():
    data = _base()
    exp = copy.deepcopy(_load('expectations/ebs_expectation.json'))
    exp['strict'] = True
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = '/api/none'
    r = evaluate_analysis_quality(data, exp)
    assert not r.passed
    assert any('should_promote_any matches too low' in x for x in r.failures)
