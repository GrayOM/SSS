#!/usr/bin/env python3
"""
Detailed inspection of review_candidates for a specific fixture.
Prints confidence/severity/title for every high-priority finding that
landed in review_candidates, so we can distinguish:
  - Demoted for low confidence alone (the bug we fixed)
  - Demoted for score/function_name/action reasons (expected/correct behavior)
"""

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
)

FIXTURE_DIR = PROJECT_ROOT / 'fixtures' / 'input'


def run_fixture(name: str):
    zip_path = FIXTURE_DIR / f'{name}.zip'
    workspace = None
    try:
        workspace = Path(prepare_workspace())
        extracted_dir = extract_zip(zip_path, workspace)
        upload_result = scan_extracted_directory(extracted_dir)
        content_result = load_file_contents(extracted_dir, upload_result)
        return analyze_console_exploitability(
            content_result.files,
            analyzer=MockConsolePocAnalyzer(),
        )
    finally:
        if workspace:
            shutil.rmtree(workspace, ignore_errors=True)


def inspect(name: str):
    print(f'\n{"=" * 60}')
    print(f'FIXTURE: {name}')
    print(f'{"=" * 60}')
    result = run_fixture(name)

    high_in_review = [(c, c.category) for c in result.review_candidates
                      if c.category in _HIGH_PRIORITY_CATEGORIES]

    low_conf_in_review = [(c, c.category) for c in result.review_candidates
                          if c.category in _HIGH_PRIORITY_CATEGORIES and c.confidence == 'low']

    print(f'\nExecutive findings: {len(result.executive_findings)}')
    print(f'Review candidates total: {len(result.review_candidates)}')
    print(f'  → High-priority in review_candidates: {len(high_in_review)}')
    print(f'  → High-priority LOW-CONF in review_candidates: {len(low_conf_in_review)}')

    if high_in_review:
        print('\nHigh-priority findings in review_candidates:')
        for c, cat in high_in_review:
            poc_code = bool(c.console_poc and c.console_poc.code) if c.console_poc else False
            fn = c.function_name or '(none)'
            page = (c.source_path or '?').split('/')[-1]
            print(f'  [{cat}]')
            print(f'    type:       {c.vulnerability_type}')
            print(f'    conf/sev:   {c.confidence}/{c.severity}')
            print(f'    function:   {fn}')
            print(f'    page:       {page}')
            print(f'    poc_code:   {poc_code}')
            print(f'    title:      {c.title[:80]}')
            if c.review_notes if hasattr(c, 'review_notes') else c.verification_notes:
                notes = c.verification_notes[:2]
                for n in notes:
                    print(f'    note:       {n[:100]}')
            print()

    if low_conf_in_review:
        print(f'[BUG CHECK] {len(low_conf_in_review)} low-conf high-priority findings demoted:')
        for c, cat in low_conf_in_review:
            print(f'  [{cat}] {c.vulnerability_type} — conf={c.confidence}')
    else:
        print('[BUG CHECK] No low-conf high-priority findings demoted. Gate working correctly.')


if __name__ == '__main__':
    names = sys.argv[1:] if len(sys.argv) > 1 else ['nafal', 'loTO', 'CIA']
    for n in names:
        inspect(n)
