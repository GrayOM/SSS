#!/usr/bin/env python3
"""
Fixture regression + quality evaluation script.

Runs the full SSS pipeline (mock backend) against each fixture ZIP and
prints structured metrics for before/after comparison.

Usage:
    python3 scripts/fixture_eval.py
"""

import json
import re
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.zip_service import extract_zip, prepare_workspace
from app.services.scan_service import scan_extracted_directory
from app.services.file_content_loader import load_file_contents
from app.services.console_poc_analysis_service import (
    analyze_console_exploitability,
    MockConsolePocAnalyzer,
    _HIGH_PRIORITY_CATEGORIES,
    _category_for,
)

FIXTURE_DIR = PROJECT_ROOT / 'fixtures' / 'input'
FIXTURES = ['nafal', 'loTO', 'CIA', 'nls', 'ebs']


# ── Quality check helpers ─────────────────────────────────────────────────────

MISLEADING_WORDING = [
    'confirmed promoted finding',
    'confirmed finding',
    'this vulnerability is confirmed',
    'confirmed vulnerability',
]

NOISY_PATTERNS = [
    r'\bsessionStorage\.getItem\b',
    r'\blocalStorage\.getItem\b',
    r'search\?',
    r'\brecommend\b',
    r'\blist\b',
    r'loading\.{0,5}state',
    r'isLoading',
]


def _text_of(obj) -> str:
    """Dump an object to a flat lowercase string for keyword search."""
    try:
        return json.dumps(obj, ensure_ascii=False, default=str).lower()
    except Exception:
        return str(obj).lower()


def check_misleading_wording(result) -> list[str]:
    txt = _text_of(result.dict() if hasattr(result, 'dict') else result)
    found = []
    for phrase in MISLEADING_WORDING:
        if phrase in txt:
            found.append(phrase)
    return found


def check_high_priority_not_demoted(result) -> list[str]:
    """Assert the is_low_conf gate is not the sole reason a high-priority finding
    was demoted.

    High-priority findings with function_name present and a confirmed PoC have
    no other known legitimate demotion reason — if confidence='low' and that
    finding is in review_candidates, the gate failed.

    Findings with function_name=None are legitimately demoted by that gate
    regardless of category, so we skip them.
    """
    violations = []
    for c in result.review_candidates:
        if (c.confidence == 'low'
                and c.category in _HIGH_PRIORITY_CATEGORIES
                and c.function_name is not None   # function_name=None is a separate gate
                and c.console_poc and c.console_poc.code):  # has a working PoC
            violations.append(
                f'FAIL: low-conf high-priority [{c.category}] demoted with function+PoC '
                f'[{c.vulnerability_type}] fn={c.function_name}'
            )
    return violations


def check_payment_false_positives(result) -> list[str]:
    """Check that 'endpoint', 'load balance', 'excessive amount' are not payment."""
    fp = []
    all_findings = result.findings + result.review_candidates
    for f in all_findings:
        cat = _category_for(f.vulnerability_type)
        vt_low = f.vulnerability_type.lower()
        if cat == 'payment_or_value_mutation':
            if 'endpoint' in vt_low and 'payment' not in vt_low and 'price' not in vt_low:
                fp.append(f'FALSE POSITIVE payment: [{f.vulnerability_type}]')
            if 'balance' in vt_low and 'account balance' not in vt_low and 'payment' not in vt_low:
                fp.append(f'FALSE POSITIVE payment (balance): [{f.vulnerability_type}]')
            if 'amount' in vt_low and 'payment amount' not in vt_low and 'price' not in vt_low:
                fp.append(f'FALSE POSITIVE payment (amount): [{f.vulnerability_type}]')
    return fp


def check_playbook_consistency(result) -> list[str]:
    """Check that each playbook's success/failure/evidence all reference the same category."""
    issues = []
    for pb in result.verification_playbooks:
        vt = pb.risk_type
        cat = _category_for(vt)
        success_txt = ' '.join(pb.success_criteria).lower()
        failure_txt = ' '.join(pb.failure_criteria).lower()
        evidence_txt = ' '.join(pb.evidence_to_capture).lower()

        # Payment: all three must mention financial terms
        if cat == 'payment_or_value_mutation':
            financial = ('amount', 'price', 'balance', 'transaction', 'mutated')
            if not any(k in success_txt for k in financial):
                issues.append(f'payment playbook missing financial term in success: [{vt}]')
            if not any(k in failure_txt for k in financial + ('server-side', 'validates')):
                issues.append(f'payment playbook missing financial term in failure: [{vt}]')

        # IDOR: all three must mention ownership / identifier
        if cat == 'idor_bola':
            idor_kw = ('another user', 'other user', 'identifier', 'different', 'ownership', 'idor')
            if not any(k in success_txt for k in idor_kw):
                issues.append(f'idor playbook missing ownership term in success: [{vt}]')
            if not any(k in failure_txt for k in idor_kw):
                issues.append(f'idor playbook missing ownership term in failure: [{vt}]')

        # Recovery: all three must mention token/code/rate
        if cat == 'account_recovery':
            rec_kw = ('token', 'code', 'rate', 'reset', 'verification')
            if not any(k in success_txt for k in rec_kw):
                issues.append(f'recovery playbook missing token/code term in success: [{vt}]')

    return issues


def sample_playbook(pb) -> dict:
    return {
        'id': pb.id,
        'risk_type': pb.risk_type,
        'confidence': pb.confidence,
        'endpoint': pb.endpoint,
        'success_criteria': pb.success_criteria[:2],
        'failure_criteria': pb.failure_criteria[:2],
        'evidence': pb.evidence_to_capture[:2],
    }


def sample_review(rc) -> dict:
    return {
        'id': rc.id,
        'title': rc.title[:80],
        'category': rc.category,
        'vulnerability_type': rc.vulnerability_type,
        'confidence': rc.confidence,
        'severity': rc.severity,
    }


# ── Main runner ───────────────────────────────────────────────────────────────

def run_fixture(name: str, zip_path: Path) -> dict:
    workspace = None
    try:
        workspace = Path(prepare_workspace())
        extracted_dir = extract_zip(zip_path, workspace)
        upload_result = scan_extracted_directory(extracted_dir)
        content_result = load_file_contents(extracted_dir, upload_result)
        result = analyze_console_exploitability(
            content_result.files,
            analyzer=MockConsolePocAnalyzer(),
        )
    except Exception as exc:
        return {'fixture': name, 'error': str(exc)}
    finally:
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)

    pp = result.project_profile
    metrics = {
        'project_type': pp.project_type if pp else 'unknown',
        'scanned_files': pp.scanned_files if pp else '?',
        'analyzed_files': pp.analyzed_files if pp else '?',
        'excluded_vendor_files': pp.excluded_vendor_files if pp else '?',
        'raw_signals': pp.raw_signals if pp else '?',
        'review_candidates': pp.review_candidates if pp else len(result.review_candidates),
        'runtime_verification_candidates': pp.runtime_verification_candidates if pp else len(result.verification_playbooks),
        'confirmed_findings': pp.confirmed_findings if pp else len(result.executive_findings),
        'finding_count': result.finding_count,
        'verification_playbook_count': len(result.verification_playbooks),
        'top_blockers': (pp.top_blockers[:3] if pp else []),
        'noise_ratio': round(pp.noise_ratio, 3) if pp else '?',
        'common_console_helper_present': bool(result.common_console_helper),
    }

    # Quality checks
    misleading = check_misleading_wording(result)
    demoted_high_priority = check_high_priority_not_demoted(result)
    payment_fp = check_payment_false_positives(result)
    playbook_consistency = check_playbook_consistency(result)

    quality = {
        'misleading_wording': misleading,
        'high_priority_demoted': demoted_high_priority,
        'payment_false_positives': payment_fp,
        'playbook_inconsistencies': playbook_consistency,
        'quality_pass': not (misleading or demoted_high_priority or payment_fp or playbook_consistency),
    }

    # Samples
    sample_pb = sample_playbook(result.verification_playbooks[0]) if result.verification_playbooks else None
    sample_rc = sample_review(result.review_candidates[0]) if result.review_candidates else None
    sample_ef = {
        'title': result.executive_findings[0].title[:80],
        'category': result.executive_findings[0].category,
        'vulnerability_type': result.executive_findings[0].vulnerability_type,
    } if result.executive_findings else None

    # Promoted finding types breakdown
    promoted_types = {}
    for ef in result.executive_findings:
        promoted_types[ef.vulnerability_type] = promoted_types.get(ef.vulnerability_type, 0) + 1

    review_types = {}
    for rc in result.review_candidates:
        review_types[rc.vulnerability_type] = review_types.get(rc.vulnerability_type, 0) + 1

    return {
        'fixture': name,
        'metrics': metrics,
        'quality': quality,
        'promoted_types': promoted_types,
        'review_types': review_types,
        'sample_playbook': sample_pb,
        'sample_review_candidate': sample_rc,
        'sample_executive_finding': sample_ef,
    }


def main():
    print('=' * 72)
    print('SSS Fixture Regression + Quality Evaluation')
    print('=' * 72)

    all_results = []
    for name in FIXTURES:
        zip_path = FIXTURE_DIR / f'{name}.zip'
        if not zip_path.exists():
            print(f'\n[{name}] SKIP — ZIP not found')
            continue
        print(f'\n[{name}] Running...', end=' ', flush=True)
        r = run_fixture(name, zip_path)
        all_results.append(r)
        if 'error' in r:
            print(f'ERROR: {r["error"]}')
        else:
            q = r['quality']
            status = 'PASS' if q['quality_pass'] else 'FAIL'
            print(f'{status}')

    print('\n\n' + '=' * 72)
    print('DETAILED RESULTS')
    print('=' * 72)

    for r in all_results:
        name = r['fixture']
        print(f'\n{"─" * 60}')
        print(f'FIXTURE: {name}')
        print(f'{"─" * 60}')

        if 'error' in r:
            print(f'  ERROR: {r["error"]}')
            continue

        m = r['metrics']
        print(f'  project_type:                  {m["project_type"]}')
        print(f'  scanned_files:                 {m["scanned_files"]}')
        print(f'  analyzed_files:                {m["analyzed_files"]}')
        print(f'  excluded_vendor_files:         {m["excluded_vendor_files"]}')
        print(f'  raw_signals:                   {m["raw_signals"]}')
        print(f'  review_candidates:             {m["review_candidates"]}')
        print(f'  runtime_verification_cands:    {m["runtime_verification_candidates"]}')
        print(f'  confirmed_findings:            {m["confirmed_findings"]}')
        print(f'  verification_playbook_count:   {m["verification_playbook_count"]}')
        print(f'  noise_ratio:                   {m["noise_ratio"]}')
        print(f'  common_console_helper:         {m["common_console_helper_present"]}')
        if m["top_blockers"]:
            print(f'  top_blockers:')
            for b in m["top_blockers"]:
                print(f'    - {b}')

        q = r['quality']
        print(f'\n  QUALITY: {"PASS" if q["quality_pass"] else "FAIL"}')
        if q['misleading_wording']:
            for x in q['misleading_wording']:
                print(f'    [WARN] misleading wording: {x}')
        if q['high_priority_demoted']:
            for x in q['high_priority_demoted']:
                print(f'    [FAIL] {x}')
        if q['payment_false_positives']:
            for x in q['payment_false_positives']:
                print(f'    [FAIL] {x}')
        if q['playbook_inconsistencies']:
            for x in q['playbook_inconsistencies']:
                print(f'    [FAIL] {x}')

        if r['promoted_types']:
            print(f'\n  Promoted (executive_findings):')
            for vt, cnt in sorted(r['promoted_types'].items(), key=lambda x: -x[1]):
                print(f'    {cnt}x {vt}')
        else:
            print(f'\n  Promoted: (none)')

        if r['review_types']:
            print(f'\n  Review candidates (top 5):')
            for vt, cnt in sorted(r['review_types'].items(), key=lambda x: -x[1])[:5]:
                print(f'    {cnt}x {vt}')

        if r['sample_playbook']:
            pb = r['sample_playbook']
            print(f'\n  Sample playbook:')
            print(f'    risk_type:  {pb["risk_type"]}')
            print(f'    confidence: {pb["confidence"]}')
            print(f'    endpoint:   {pb["endpoint"]}')
            print(f'    success[0]: {pb["success_criteria"][0][:100] if pb["success_criteria"] else "(none)"}')
            print(f'    failure[0]: {pb["failure_criteria"][0][:100] if pb["failure_criteria"] else "(none)"}')
            print(f'    evidence[0]:{pb["evidence"][0][:100] if pb["evidence"] else "(none)"}')

        if r['sample_review_candidate']:
            rc = r['sample_review_candidate']
            print(f'\n  Sample review candidate:')
            print(f'    [{rc["category"]}] {rc["title"]}')
            print(f'    type: {rc["vulnerability_type"]}, conf: {rc["confidence"]}, sev: {rc["severity"]}')

        if r['sample_executive_finding']:
            ef = r['sample_executive_finding']
            print(f'\n  Sample executive finding:')
            print(f'    [{ef["category"]}] {ef["title"]}')

    # Summary table
    print('\n\n' + '=' * 72)
    print('SUMMARY TABLE')
    print('=' * 72)
    print(f'{"Fixture":<10} {"Type":<25} {"Files":>6} {"Sigs":>5} {"Rev":>5} {"Play":>5} {"Exec":>5} {"Noise":>7} {"QA"}')
    print('-' * 72)
    for r in all_results:
        if 'error' in r:
            print(f'{r["fixture"]:<10} ERROR')
            continue
        m = r['metrics']
        q = r['quality']
        qa = 'PASS' if q['quality_pass'] else 'FAIL'
        print(
            f'{r["fixture"]:<10} {str(m["project_type"]):<25} '
            f'{str(m["analyzed_files"]):>6} {str(m["raw_signals"]):>5} '
            f'{str(m["review_candidates"]):>5} {str(m["verification_playbook_count"]):>5} '
            f'{str(m["confirmed_findings"]):>5} {str(m["noise_ratio"]):>7} {qa}'
        )

    total_issues = sum(
        len(r['quality']['misleading_wording']) +
        len(r['quality']['high_priority_demoted']) +
        len(r['quality']['payment_false_positives']) +
        len(r['quality']['playbook_inconsistencies'])
        for r in all_results if 'error' not in r
    )
    total_qa_pass = sum(1 for r in all_results if 'error' not in r and r['quality']['quality_pass'])
    total_run = sum(1 for r in all_results if 'error' not in r)

    print(f'\nQuality issues found: {total_issues}')
    print(f'QA pass: {total_qa_pass}/{total_run} fixtures')
    if total_issues == 0:
        print('\nVERDICT: All quality checks passed. Safe to commit.')
    else:
        print('\nVERDICT: Quality issues found — investigate before committing.')


if __name__ == '__main__':
    main()
