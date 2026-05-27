import json
from pathlib import Path

from app.services.analysis_quality_evaluator import evaluate_analysis_quality

ROOT = Path(__file__).parent / 'fixtures'


def _load(rel):
    return json.loads((ROOT / rel).read_text())


def test_nls_recommend_review_passes():
    r = evaluate_analysis_quality(_load('analysis_results/nls_result.json'), _load('expectations/nls_expectation.json'))
    assert r.passed


def test_nls_recommend_promoted_fails():
    data = _load('analysis_results/nls_result.json')
    data['readable_analysis']['verification_playbooks'] = [{"endpoint": "/header/recommend_search.do", "method": "GET", "console_code": "x", "user_action_hint": "대상 기능 버튼 클릭", "page_hint": "해당 기능 화면"}]
    r = evaluate_analysis_quality(data, _load('expectations/nls_expectation.json'))
    assert not r.passed


def test_ebs_zero_playbooks_fails():
    data = _load('analysis_results/ebs_result.json')
    data['readable_analysis']['verification_playbooks'] = []
    r = evaluate_analysis_quality(data, _load('expectations/ebs_expectation.json'))
    assert not r.passed


def test_cia_compressed_promoted_fails():
    data = _load('analysis_results/cia_result.json')
    data['readable_analysis']['verification_playbooks'] = [{"endpoint": "/api/x", "method": "GET", "console_code": "x", "user_action_hint": "검증", "page_hint": "화면", "limitations": ["compressed"]}]
    r = evaluate_analysis_quality(data, _load('expectations/cia_expectation.json'))
    assert not r.passed


def test_unknown_endpoint_playbook_fails():
    data = _load('analysis_results/ebs_result.json')
    data['readable_analysis']['verification_playbooks'][0]['endpoint'] = 'UNKNOWN'
    r = evaluate_analysis_quality(data, _load('expectations/ebs_expectation.json'))
    assert not r.passed


def test_missing_console_code_playbook_fails():
    data = _load('analysis_results/ebs_result.json')
    data['readable_analysis']['verification_playbooks'][0]['console_code'] = None
    r = evaluate_analysis_quality(data, _load('expectations/ebs_expectation.json'))
    assert not r.passed


def test_generic_action_rate_exceeded_fails():
    data = _load('analysis_results/ebs_result.json')
    data['readable_analysis']['verification_playbooks'] = [
        {"endpoint": "/user/chkMobiSendAjax", "method": "POST", "console_code": "x", "user_action_hint": "대상 기능 버튼 클릭", "page_hint": "해당 기능 화면"}
    ]
    r = evaluate_analysis_quality(data, _load('expectations/ebs_expectation.json'))
    assert not r.passed
