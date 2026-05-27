from pathlib import Path
import re


def test_no_legacy_sample_nicknames_in_fixtures_docs_scripts():
    roots = [Path('tests/fixtures'), Path('scripts'), Path('docs')]
    patterns = [
        r'"sample"\s*:\s*"ebs"', r'"sample"\s*:\s*"nls"', r'"sample"\s*:\s*"cia"',
        r'\bebs_result\b', r'\bnls_result\b', r'\bcia_result\b', r'\bnafal_result\b',
        r'\bebs_expectation\b', r'\bnls_expectation\b', r'\bcia_expectation\b', r'\bnafal_expectation\b',
        r'\bebs\\', r'\bnls\\', r'\bCIA\\'
    ]
    compiled = [re.compile(p) for p in patterns]
    hits = []
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob('*'):
            if not p.is_file():
                continue
            txt = p.read_text(encoding='utf-8', errors='ignore')
            for cp in compiled:
                if cp.search(txt):
                    hits.append((str(p), cp.pattern))
    assert hits == []
