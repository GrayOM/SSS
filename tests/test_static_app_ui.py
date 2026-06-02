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


def test_static_app_js_renders_observational_poc_not_console_poc():
    js = _app_js()

    # observational_poc.code is the source for observational review candidates
    assert 'observational_poc' in js
    assert 'obsPoc' in js
    assert 'safeObsCode' in js
    assert "poc_generation_status === 'observational'" in js
    assert 'isObservational' in js


def test_static_app_js_observational_review_wording():
    js = _app_js()

    assert 'Runtime request discovery hint' in js
    assert 'Install common_console_helper first' in js
    assert 'This is still not a confirmed vulnerability' in js


def test_static_app_js_hook_guard_prevents_long_code():
    js = _app_js()

    # isSafeReviewCode must check for all five hook marker strings
    assert 'HOOK_MARKERS' in js
    assert 'isSafeReviewCode' in js
    assert 'window.fetch = async function' in js   # marker listed in guard
    assert 'XMLHttpRequest.prototype.open' in js   # marker listed in guard
    assert 'axios.interceptors.request.use' in js  # marker listed in guard
    assert 'SSS_REVIEW_POC_STATE' in js            # marker listed in guard
    assert 'TARGET_ENDPOINT =' in js               # marker listed in guard
    assert 'safeObsCode' in js
    assert 'safePocCode' in js


def test_static_app_js_manual_plan_still_rendered():
    js = _app_js()

    assert 'renderManualPocPlan' in js
    assert 'manual_poc_plan' in js
    assert "poc_generation_status === 'manual_plan'" in js
    assert 'isManualPlan' in js


def test_static_app_js_promoted_playbooks_use_short_console_code():
    js = _app_js()

    # Promoted playbooks section renders pb.console_code (short SSS_POC.find code)
    assert 'renderVerificationPlaybooks' in js
    assert 'pb.console_code' in js or 'console_code' in js
    # The promoted section must appear before manual review section
    assert js.index('Promoted Verification Playbooks') < js.index('Manual Review Candidates')
