#!/usr/bin/env python3
"""
verify_goal.py -- acceptance test for endpoint-resolution + short-PoC goal.
Exit 0 if all checks pass, non-zero otherwise.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.schemas import FileContent
from app.services.console_poc_analysis_service import (
    analyze_console_exploitability, MockConsolePocAnalyzer,
)
from app.services.poc_templates import INTERCEPTOR_SIGS

PASS = 0
FAIL = 0

def fc(path, content):
    return FileContent(
        path=path, extension='js', size=len(content), priority=1,
        reason_code='INCLUDED', content_hash='h', content=content,
    )

def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        print(f'PASS  {name}')
        PASS += 1
    else:
        print(f'FAIL  {name}' + (f': {detail}' if detail else ''))
        FAIL += 1

FORBIDDEN_PROMOTED = (
    'window.SSS_POC.find(',
    'window.SSS_POC',
    'window.SSS_REVIEW_POC',
    'XMLHttpRequest.prototype',
    'fetch = new Proxy',
    'addEventListener("fetch"',
    'SSS_POC.find',
    'SSS_REVIEW_POC',
)

def non_empty_line_count(code):
    return len([line for line in (code or '').splitlines() if line.strip()])

def promoted_for(result, needle):
    return [p for p in result.verification_playbooks if needle in (p.endpoint or '')]

# ---------------------------------------------------------------------------
# G1 -- base-URL-only endpoints resolve and promote
# ---------------------------------------------------------------------------
g1_files = [
    fc('src/LoginPage.js',
       "function handleLogin() { axios.post('{API_BASE_URL}/login', { email, password }); }\n"
       "<button onClick={handleLogin}>Login</button>"),
]
r1 = analyze_console_exploitability(g1_files, analyzer=MockConsolePocAnalyzer())
login_pb = [p for p in r1.verification_playbooks
            if '/login' in (p.endpoint or '') and p.risk_type != 'DOM XSS']

check('G1a: {API_BASE_URL}/login POST promotes',
      len(login_pb) > 0,
      f'verification_playbooks={[(p.endpoint, p.risk_type) for p in r1.verification_playbooks]}')

if login_pb:
    code = login_pb[0].console_code or ''
    check('G1b: console_code contains fetch("/login"',
          'fetch("/login"' in code or "fetch('/login'" in code,
          f'code={code[:200]}')
    check('G1c: console_code does NOT contain window.SSS_POC.find(',
          'window.SSS_POC.find(' not in code,
          f'code={code[:200]}')
    check('G1d: console_code contains no helper namespace',
          not any(sig in code for sig in FORBIDDEN_PROMOTED),
          f'sigs found={[s for s in FORBIDDEN_PROMOTED if s in code]}')
    check('G1e: console_code <=12 lines',
          non_empty_line_count(code) <= 12,
          f'lines={non_empty_line_count(code)}')
    check('G1f: common_console_helper is not required',
          r1.common_console_helper is None,
          f'helper_len={len(r1.common_console_helper) if r1.common_console_helper else "None"}')
else:
    for sub in ('G1b', 'G1c', 'G1d', 'G1e', 'G1f'):
        check(f'{sub}: skipped (no playbook)', False, 'no playbook to inspect')

# ---------------------------------------------------------------------------
# G2 -- path-param endpoints promote as self-contained, helper-free PoCs
# ---------------------------------------------------------------------------
g2_files = [
    fc('src/AuctionPage.js',
       "function handleBid() { axios.post('/api/auction/{item.id}/bid', { amount }); }\n"
       "<button onClick={handleBid}>Bid</button>"),
]
r2 = analyze_console_exploitability(g2_files, analyzer=MockConsolePocAnalyzer())
bid_pb = [p for p in r2.verification_playbooks
          if 'bid' in (p.endpoint or '').lower() or 'auction' in (p.endpoint or '').lower()]

check('G2a: /api/auction/{item.id}/bid POST promotes',
      len(bid_pb) > 0,
      f'playbooks={[(p.endpoint, p.risk_type) for p in r2.verification_playbooks]}')

if bid_pb:
    code2 = bid_pb[0].console_code or ''
    check('G2b: console_code derives itemId from runtime/page sources before fallback',
          'const itemId =' in code2
          and 'location.search' in code2
          and 'location.pathname.match' in code2
          and '[data-item-id]' in code2
          and 'REPLACE_WITH_ITEM_ID' in code2,
          f'code={code2[:300]}')
    check('G2c: console_code contains runtime-aware template-literal fetch path',
          'fetch(`/api/auction/${itemId}/bid' in code2,
          f'code={code2[:300]}')
    check('G2d: console_code does NOT contain window.SSS_POC.find(',
          'window.SSS_POC.find(' not in code2,
          f'code={code2[:300]}')
    check('G2e: console_code is interceptor-free',
          not any(sig in code2 for sig in FORBIDDEN_PROMOTED),
          f'sigs={[s for s in FORBIDDEN_PROMOTED if s in code2]}')
    check('G2f: console_code <=12 lines',
          non_empty_line_count(code2) <= 12,
          f'lines={non_empty_line_count(code2)}')
else:
    for sub in ('G2b', 'G2c', 'G2d', 'G2e', 'G2f'):
        check(f'{sub}: skipped (no playbook)', False, 'no playbook to inspect')

# ---------------------------------------------------------------------------
# G3 -- no long-PoC leakage; common_console_helper=None when all PoCs are self-contained
# ---------------------------------------------------------------------------
# Use a fixture that should give at least one promoted playbook (all self-contained)
g3_files = [
    fc('src/Pay.jsx',
       "function submitOrder() { axios.post('/api/orders/pay', { amount }); }\n"
       "<button onClick={submitOrder}>Pay now</button>"),
]
r3 = analyze_console_exploitability(g3_files, analyzer=MockConsolePocAnalyzer())

all_self_contained = all(
    not any(sig in (pb.console_code or '') for sig in FORBIDDEN_PROMOTED)
    for pb in r3.verification_playbooks
)

check('G3a: common_console_helper is None when all PoCs self-contained',
      r3.common_console_helper is None,
      f'helper_len={len(r3.common_console_helper) if r3.common_console_helper else "None"}')

check('G3b: all promoted PoCs are self-contained (no SSS_POC.find)',
      all_self_contained,
      'some playbook still uses SSS_POC.find or INTERCEPTOR_SIG')

for pb in r3.verification_playbooks:
    code3 = pb.console_code or ''
    check(f'G3c: playbook {pb.endpoint} <=12 lines',
          non_empty_line_count(code3) <= 12,
          f'lines={non_empty_line_count(code3)}')
    check(f'G3d: playbook {pb.endpoint} interceptor-free',
          not any(sig in code3 for sig in FORBIDDEN_PROMOTED),
          f'sigs={[s for s in FORBIDDEN_PROMOTED if s in code3]}')

# Additional required base URL variants exercise the same production paths.
variant_files = [
    fc('src/AdminAdd.jsx',
       'function addNumbers(){axios.post(`${API_BASE_URL}/admin/add-numbers`, { a, b });}\n'
       '<button onClick={addNumbers}>Add</button>'),
    fc('src/Lotto.jsx',
       'function generateLotto(){axios.post(API_BASE_URL + "/generate-lotto", {});}\n'
       '<button onClick={generateLotto}>Generate</button>'),
    fc('src/ApiClient.js',
       'function login(){axios.create({ baseURL: API_BASE_URL }).post("/login", { email, password });}\n'
       '<button onClick={login}>Login</button>'),
    fc('src/UnknownPath.js',
       'function unknown(){axios.post("{API_BASE_URL}/{UNKNOWN_PATH}", {});}\n'
       '<button onClick={unknown}>Run</button>'),
]
rv = analyze_console_exploitability(variant_files, analyzer=MockConsolePocAnalyzer())
check('G3e: ${API_BASE_URL}/admin/add-numbers promotes',
      bool(promoted_for(rv, '/admin/add-numbers')),
      f'playbooks={[(p.endpoint, p.method) for p in rv.verification_playbooks]}')
check('G3f: API_BASE_URL + "/generate-lotto" promotes',
      bool(promoted_for(rv, '/generate-lotto')),
      f'playbooks={[(p.endpoint, p.method) for p in rv.verification_playbooks]}')
check('G3g: axios.create({ baseURL }).post("/login") promotes',
      bool(promoted_for(rv, '/login')),
      f'playbooks={[(p.endpoint, p.method) for p in rv.verification_playbooks]}')
check('G3h: unknown path placeholder remains manual',
      not promoted_for(rv, '/{UNKNOWN_PATH}'),
      f'playbooks={[(p.endpoint, p.method) for p in rv.verification_playbooks]}')

# ---------------------------------------------------------------------------
# G4 -- destructive block still intact
# ---------------------------------------------------------------------------
g4_files = [
    fc('src/AdminPage.js',
       "function handleRefund() { axios.post('{API_BASE_URL}/admin/refund', { orderId }); }\n"
       "<button onClick={handleRefund}>Refund</button>"),
    fc('src/DelPage.js',
       "function handleDelete() { axios.delete('/api/user/1'); }\n"
       "<button onClick={handleDelete}>Delete</button>"),
]
r4 = analyze_console_exploitability(g4_files, analyzer=MockConsolePocAnalyzer())

refund_pb = [p for p in r4.verification_playbooks if 'refund' in (p.endpoint or '').lower()]
delete_pb = [p for p in r4.verification_playbooks if 'delete' in (p.endpoint or '').lower() or p.method == 'DELETE']

check('G4a: {API_BASE_URL}/admin/refund POST is NOT promoted',
      len(refund_pb) == 0,
      f'refund_playbooks={[(p.endpoint, p.method) for p in refund_pb]}')

check('G4b: DELETE /api/user/1 is NOT promoted',
      len(delete_pb) == 0,
      f'delete_playbooks={[(p.endpoint, p.method) for p in delete_pb]}')

# Verify no destructive PoC codes were generated anywhere
all_codes = [
    (pb.console_code or '')
    for pb in r4.verification_playbooks
]
check('G4c: no promoted PoC code contains destructive action',
      not any('refund' in c.lower() or ('delete' in c.lower() and 'DELETE' in c) for c in all_codes),
      f'codes={all_codes[:2]}')

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print()
print(f'verify_goal: {PASS} passed, {FAIL} failed')
sys.exit(0 if FAIL == 0 else 1)
