import json
from pathlib import Path

from app.services.analysis_quality_evaluator import evaluate_analysis_quality
from app.services.corpus_learning_service import build_generalization_learning_report

ROOT = Path(__file__).parent / 'fixtures'


def _load(p):
    return json.loads((ROOT / p).read_text())


def test_corpus_learning_report_contains_taxonomy_and_suggestions():
    result = _load('analysis_results/pass_base_result.json')
    exp = _load('expectations/sample_jquery_template_large_expectation.json')
    qr = evaluate_analysis_quality(result, exp).to_dict()
    rep = build_generalization_learning_report('sample_jquery_template_large', result, qr)
    assert rep['sample_id'] == 'sample_jquery_template_large'
    assert isinstance(rep['common_failure_patterns'], list)
    assert isinstance(rep['suggested_generalization_rules'], list)
    assert all('nafal' not in s.lower() for s in rep['suggested_generalization_rules'])
