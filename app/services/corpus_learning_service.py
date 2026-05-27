"""Corpus learning here means evaluation-driven rule improvement suggestions, not model fine-tuning."""
from __future__ import annotations

from typing import Any


def build_generalization_learning_report(sample_name: str, analysis_result: dict[str, Any], quality_report: dict[str, Any]) -> dict[str, Any]:
    ra = analysis_result.get('readable_analysis', {})
    pu = ra.get('project_understanding', {})
    metrics = quality_report.get('metrics', {})
    failures = quality_report.get('failures', [])
    patterns = []
    if any('endpoint UNKNOWN' in f for f in failures):
        patterns.append('endpoint_unknown')
    if any('missing console_code' in f for f in failures):
        patterns.append('missing_poc_code')
    if any('generic action rate' in f for f in failures):
        patterns.append('generic_action_hint')
    suggestions = [
        'Strengthen UI-event/API linking from selectors/forms across frameworks',
        'Prefer observational PoC generation when executable promotion is not possible',
        'Expand endpoint token categories without project-specific hardcoding',
    ]
    return {
        'sample_name': sample_name,
        'framework': pu.get('framework'),
        'api_inventory_count': metrics.get('api_inventory_count', 0),
        'ui_event_count': metrics.get('ui_event_count', 0),
        'api_ui_linked_count': metrics.get('api_ui_linked_count', 0),
        'playbook_count': metrics.get('verification_playbooks_count', 0),
        'review_count': metrics.get('review_candidates_count', 0),
        'poc_generated_count': metrics.get('poc_generated_count', 0),
        'poc_missing_count': metrics.get('poc_missing_count', 0),
        'common_failure_patterns': patterns,
        'suggested_generalization_rules': suggestions,
        'files_to_improve': ['app/services/api_candidate_extractor.py', 'app/services/source_intelligence.py', 'app/services/console_poc_analysis_service.py'],
        'tests_to_add': ['tests/test_source_intelligence.py', 'tests/test_console_poc_analysis_service.py'],
    }
