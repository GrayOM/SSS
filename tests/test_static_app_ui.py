from pathlib import Path


APP_JS = Path(__file__).resolve().parents[1] / 'app' / 'static' / 'app.js'


def _app_js() -> str:
    return APP_JS.read_text(encoding='utf-8')


def test_static_app_js_separates_promoted_playbooks_from_review_candidates():
    js = _app_js()

    assert 'Promoted Verification Playbooks' in js
    assert 'Manual Review Candidates' in js
    assert 'Not automatically confirmed vulnerability' in js
    assert 'review_candidates ?? []' in js
    assert 'renderVerificationPlaybooks(playbooks)' in js
    assert 'renderManualReviewCandidates(reviewCandidates)' in js
    assert js.index('renderVerificationPlaybooks(playbooks)') < js.index('renderManualReviewCandidates(reviewCandidates)')


def test_static_app_js_common_helper_usage_guidance():
    js = _app_js()

    assert 'Step 1:' in js
    assert 'paste common_console_helper once' in js
    assert 'Step 2:' in js
    assert 'perform the documented page/action' in js
    assert 'Step 3:' in js
    assert 'run the short finding-specific console_code' in js
    assert 'Step 4:' in js
    assert 'use mutation/replay only after approval' in js
