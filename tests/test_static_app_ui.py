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


# -- loTO / NAFAL real-world regression: zero-playbook UI behavior ----------

def test_static_app_js_no_helper_shown_when_no_playbooks():
    js = _app_js()

    # renderCommonConsoleHelper must accept hasPlaybooks argument
    assert 'hasPlaybooks' in js
    assert 'renderCommonConsoleHelper(body.readable_analysis, playbooks.length > 0)' in js


def test_static_app_js_zero_playbook_message():
    js = _app_js()

    assert 'No browser-console-runnable PoC was generated' in js
    assert 'Only manual review candidates were found' in js
    # The zero-playbook message must not invite the user to paste anything
    # (the word "paste" only appears in the helper block that is hidden when no playbooks)
    # Verify the zero-playbook branch does NOT contain "paste common_console_helper"
    zero_block_start = js.index('No browser-console-runnable PoC was generated')
    zero_block_end   = js.index('Only manual review candidates were found')
    zero_block = js[zero_block_start:zero_block_end + 200]
    assert 'paste common_console_helper' not in zero_block


def test_static_app_js_helper_undefined_explanation():
    js = _app_js()

    # When helper IS shown, explain that undefined output is normal
    assert 'undefined' in js
    assert '[SSS PoC] common helper installed' in js


def test_static_app_js_manual_plan_no_runnable_poc_banner():
    js = _app_js()

    assert 'No runnable Console PoC' in js
    assert 'manual verification only' in js
    # The banner must be conditional on isManualPlan
    assert "isManualPlan ? `<p" in js or "isManualPlan ?" in js


def test_static_app_js_manual_plan_no_paste_into_console():
    js = _app_js()

    # "Paste into Console" wording must never appear inside manual_plan card template
    # It only appears inside the helper block (shown only when hasPlaybooks === true)
    # and inside the observational/capture sections (not isManualPlan paths)
    # Check that the manual_plan branch (renderManualPocPlan) does not emit "Paste into Console"
    assert 'renderManualPocPlan' in js
    manual_fn_start = js.index('function renderManualPocPlan')
    manual_fn_end   = js.index('\n}', manual_fn_start) + 2
    manual_fn = js[manual_fn_start:manual_fn_end]
    assert 'Paste into Console' not in manual_fn
    assert 'paste' not in manual_fn.lower()


def test_static_app_js_unresolved_endpoint_wording():
    js = _app_js()

    # Review card must include explicit "No runnable Console PoC" label
    assert 'No runnable Console PoC' in js
    # Reason field shown for all review candidates
    assert 'poc_generation_reason' in js


def test_static_app_js_no_code_block_for_manual_plan():
    js = _app_js()

    # For manual_plan: only renderManualPocPlan is called - no renderVerificationCode
    # Verify: the renderVerificationCode call in manual review is guarded by isObservational/safePocCode
    # (i.e., it never fires when isManualPlan is true)
    assert 'isObservational && safeObsCode' in js
    assert '!isManualPlan && !isObservational && safePocCode' in js
    # isManualPlan path calls renderManualPocPlan, not renderVerificationCode
    manual_plan_branch = 'isManualPlan ? renderManualPocPlan'
    assert manual_plan_branch in js


# -- Mojibake regression: app.js must be ASCII-only outside Korean summary labels ------

def test_static_app_js_no_mojibake_chars():
    """app.js must not contain em-dash, en-dash, right-arrow, box-drawing, or warning-sign."""
    js = _app_js()
    MOJIBAKE = {
        '\u2014': 'EM DASH',
        '\u2013': 'EN DASH',
        '\u2192': 'RIGHT ARROW',
        '\u2500': 'BOX DRAWING LIGHT HORIZONTAL',
        '\u26a0': 'WARNING SIGN',
        '\ufffd': 'REPLACEMENT CHARACTER',
    }
    for char, name in MOJIBAKE.items():
        assert char not in js, f'app.js contains U+{ord(char):04X} {name}'


def test_static_app_js_helper_title_uses_ascii_dash():
    """Helper h3 title must use ASCII hyphen, not em-dash."""
    js = _app_js()
    assert 'Common Console Helper - paste once before running any playbook' in js
    assert 'Common Console Helper \u2014' not in js


def test_static_app_js_manual_banner_uses_ascii_dash():
    """Manual-plan banner must use ASCII hyphen, not em-dash or warning sign."""
    js = _app_js()
    assert 'No runnable Console PoC - manual verification only' in js
    assert '\u26a0' not in js
    assert '\u2014' not in js
