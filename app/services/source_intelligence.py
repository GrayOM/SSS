import re
from collections import defaultdict

from app.models.schemas import ApiInventoryItem, BusinessFlow, FileContent, ProjectPage, ProjectRoute, ProjectUnderstandingResult, UiEventCandidate
from app.services.api_candidate_extractor import extract_api_call_candidates, extract_ui_handler_candidates
def _find_enclosing_function_block(content: str, line_number: int) -> tuple[str | None, int, int, str] | None:
    lines = content.splitlines() or ['']
    idx = max(0, min(len(lines) - 1, line_number - 1))
    pats = [
        re.compile(r'function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\('),
        re.compile(r'const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{'),
    ]
    for s in range(idx, -1, -1):
        line = lines[s]
        m = None
        for p in pats:
            m = p.search(line)
            if m:
                break
        if not m:
            continue
        depth = 0
        opened = False
        for e in range(s, len(lines)):
            depth += lines[e].count('{')
            if lines[e].count('{') > 0:
                opened = True
            depth -= lines[e].count('}')
            if opened and depth <= 0 and e >= idx:
                return (m.group(1), s + 1, e + 1, '\n'.join(lines[s:e + 1]))
    return None


def _detect_framework(files: list[FileContent]) -> str | None:
    text = '\n'.join(f.content for f in files).lower()
    if any(f.path.lower().endswith('.vue') for f in files) or any(k in text for k in ['@click', 'v-on:', 'createapp', 'v-model']):
        return 'Vue'
    if any(k in text for k in ['import react', "from 'react'", 'reactdom.createroot', '<route', 'onclick={', 'onsubmit={']):
        return 'React'
    if any(k in text for k in ['$.ajax', '.on(\'click\'', 'document.ready', '$(']):
        return 'jQuery'
    if any(k in text for k in ['addeventlistener', 'queryselector']):
        return 'Vanilla'
    return None


def _risk_category(method: str, endpoint: str, params: list[str]) -> str | None:
    low = endpoint.lower()
    p = {x.lower() for x in params}
    if any(k in low for k in ('payment', 'order', 'checkout', 'pay', 'billing', 'iamport', 'stripe')):
        return 'payment'
    if any(k in low for k in ('bid', 'auction')):
        return 'auction'
    if any(k in low for k in ('verify-code', 'send-verification', 'reset-password', 'password')):
        return 'account_recovery'
    if any(k in low for k in ('wallet', 'point', 'charge')):
        return 'wallet_point'
    if any(k in low for k in ('/session', '/auth/me', '/api/me', '/profile/me')) and method == 'GET':
        return 'session_check'
    if any(k in p for k in ('userid', 'memberid', 'orderid')) or re.search(r'\{[^}]+id\}', endpoint, re.I):
        return 'idor_candidate'
    if any(k in low for k in ('admin', 'role')) or any(k in p for k in ('role', 'usertype', 'isadmin')):
        return 'authorization'
    return None


def _page_hint(route_paths: list[str], titles: list[str], component_name: str | None, source_path: str, risk_categories: list[str]) -> str | None:
    base = ' '.join(route_paths + titles + [component_name or '', source_path]).lower()
    if any(k in base for k in ('/payment', '/checkout', 'payment', 'checkout', 'order')) or 'payment' in risk_categories:
        return '결제/주문 화면'
    if any(k in base for k in ('/auction', '/bid', 'auction', 'bid')) or 'auction' in risk_categories:
        return '경매/입찰 화면'
    if any(k in base for k in ('/find-password', 'reset', 'verify', 'password')) or 'account_recovery' in risk_categories:
        return '계정 복구/인증 화면'
    if any(k in base for k in ('/wallet', '/point', '/charge', 'wallet', 'point')) or 'wallet_point' in risk_categories:
        return '지갑/포인트 화면'
    if any(k in base for k in ('/admin', 'dashboard', 'manage')) or 'authorization' in risk_categories:
        return '관리자/관리 화면'
    return None


def build_project_understanding(files: list[FileContent]) -> ProjectUnderstandingResult:
    framework = _detect_framework(files)
    ui_raw = extract_ui_handler_candidates(files)
    api = extract_api_call_candidates(files).candidates

    routes: list[ProjectRoute] = []
    pages: list[ProjectPage] = []
    ui_events = [UiEventCandidate(**u) for u in ui_raw]

    risk_by_file: dict[str, list[str]] = defaultdict(list)
    for c in api:
        r = _risk_category(c.method, c.endpoint, c.parameters)
        if r:
            risk_by_file[c.source_path].append(r)

    for f in files:
        lines = f.content.splitlines()
        route_re = re.compile(r'<Route\s+path=["\']([^"\']+)["\']\s+(?:element=\{<([A-Za-z0-9_]+)|component=\{?([A-Za-z0-9_]+))')
        comp_name = None
        mcomp = re.search(r'export\s+default\s+function\s+([A-Za-z_][A-Za-z0-9_]*)|function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(', f.content)
        if mcomp:
            comp_name = next(x for x in mcomp.groups() if x)
        titles = [m.group(1).strip() for m in re.finditer(r'<h[1-3][^>]*>([^<]{1,120})</h[1-3]>', f.content, re.I)]
        pg = ProjectPage(source_path=f.path, component_name=comp_name, title_texts=titles)
        for i, line in enumerate(lines, start=1):
            m = route_re.search(line)
            if m:
                path = m.group(1)
                comp = m.group(2) or m.group(3)
                routes.append(ProjectRoute(path=path, component=comp, source_path=f.path, line=i))
                pg.route_paths.append(path)
        pg.page_hint = _page_hint(pg.route_paths, pg.title_texts, pg.component_name, f.path, risk_by_file.get(f.path, []))
        pages.append(pg)

    inv: list[ApiInventoryItem] = []
    for c in api:
        src = next((f for f in files if f.path == c.source_path), None)
        fn = None
        if src:
            blk = _find_enclosing_function_block(src.content, c.start_line)
            fn = blk[0] if blk else None
        linked = [u for u in ui_raw if u.get('source_path') == c.source_path and (u.get('handler_name') == fn or abs(u.get('start_line', 0) - c.start_line) <= 8)]
        ui_handler = linked[0].get('handler_name') if linked and linked[0].get('handler_name') else (fn if any(u.get('handler_name') == fn and u.get('source_path') == c.source_path for u in ui_raw) else None)
        ui_event_text = next((u.get('element_text') for u in linked if u.get('element_text')), None)
        ui_event_type = next((u.get('ui_event') for u in linked if u.get('ui_event') not in {'function_hint', 'element_text'}), None)
        interaction_confidence = 'high' if (ui_handler and ui_event_type) else ('medium' if ui_handler else 'low')
        inv.append(ApiInventoryItem(
            source_path=c.source_path, function_name=fn, method=c.method, endpoint=c.endpoint, sink=c.sink,
            parameters=c.parameters, start_line=c.start_line, end_line=c.end_line, ui_event_handler=ui_handler,
            ui_event_text=ui_event_text, ui_event_type=ui_event_type, interaction_confidence=interaction_confidence,
            risk_category=_risk_category(c.method, c.endpoint, c.parameters)
        ))

    flow_map: dict[str, dict] = defaultdict(lambda: {'source_paths': set(), 'handlers': set(), 'endpoints': set(), 'reasons': set()})
    for item in inv:
        ftype = item.risk_category or 'generic_review'
        v = flow_map[ftype]
        v['source_paths'].add(item.source_path)
        if item.function_name:
            v['handlers'].add(item.function_name)
        v['endpoints'].add(item.endpoint)
        if item.risk_category:
            v['reasons'].add(f'risk_category={item.risk_category}')
    flows = [BusinessFlow(flow_type=k, source_paths=sorted(v['source_paths']), handlers=sorted(v['handlers']), endpoints=sorted(v['endpoints']), reasons=sorted(v['reasons'])) for k, v in flow_map.items()]

    auth_sources = sorted({i.source_path for i in inv if i.risk_category in {'authorization', 'session_check'}})
    storage_keys = sorted({k for f in files for k in re.findall(r"(?:localStorage|sessionStorage)\.setItem\(['\"]([^'\"]+)['\"]", f.content)})

    return ProjectUnderstandingResult(
        framework=framework,
        routes=routes,
        pages=pages,
        ui_events=ui_events,
        api_inventory=inv,
        business_flows=flows,
        auth_sources=auth_sources,
        storage_keys=storage_keys,
        unknowns=[]
    )
