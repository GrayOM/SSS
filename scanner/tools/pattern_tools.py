"""Regex-based pattern matching tools shared across analysis agents."""
from __future__ import annotations
import re

# ── JS dangerous sinks ────────────────────────────────────────────────────────
SINK_PATTERNS: list[tuple[str, str, str]] = [
    (r'\.innerHTML\s*=\s*[^"\']', "innerHTML assignment", "DOM XSS"),
    (r'\.outerHTML\s*=\s*[^"\']', "outerHTML assignment", "DOM XSS"),
    (r'document\.write\s*\(', "document.write()", "DOM XSS"),
    (r'eval\s*\(', "eval()", "Code Injection"),
    (r'setTimeout\s*\(\s*[^"\']', "setTimeout(string)", "Code Injection"),
    (r'setInterval\s*\(\s*[^"\']', "setInterval(string)", "Code Injection"),
    (r'\.src\s*=\s*location', "src from location", "DOM XSS"),
    (r'postMessage\s*\(', "postMessage()", "postMessage misuse"),
    (r'addEventListener\s*\(\s*["\']message["\']', "message listener", "postMessage receiver"),
]

# ── Secret patterns ────────────────────────────────────────────────────────────
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "API Key", "High"),
    (r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', "Secret/Password", "Critical"),
    (r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "JWT Token", "High"),
    (r'(?i)(aws_access_key_id|aws_secret)\s*[:=]\s*["\']([A-Za-z0-9+/]{20,})["\']', "AWS Key", "Critical"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "High"),
    (r'(?i)(bearer\s+)([A-Za-z0-9\-_.~+/]+=*)', "Bearer Token", "High"),
    (r'(?i)(private[_-]?key|privatekey)\s*[:=]\s*["\']([^"\']{16,})["\']', "Private Key", "Critical"),
    (r'(?i)authorization\s*[:=]\s*["\']([^"\']{8,})["\']', "Auth Header Value", "Medium"),
]

# ── Role / debug patterns ─────────────────────────────────────────────────────
ROLE_PATTERNS: list[tuple[str, str]] = [
    (r'if\s*\(\s*(?:role|userRole|user\.role)\s*===?\s*["\']admin["\']', "Client-side admin check"),
    (r'if\s*\(\s*(?:isAdmin|is_admin|admin)\s*\)', "isAdmin flag check"),
    (r'if\s*\(\s*debug\s*(?:===?|==)\s*true\b', "Debug flag check"),
    (r'(?i)(testMode|test_mode|internalMode|internal_mode)\s*[:=]\s*true', "Test/Internal mode"),
    (r'(?i)(featureFlag|feature_flag)\s*[:=]', "Feature flag"),
    (r'if\s*\(\s*(?:isSuperUser|superuser|superUser)\s*\)', "Superuser check"),
]

# ── API patterns ──────────────────────────────────────────────────────────────
API_PATTERNS: list[tuple[str, str]] = [
    (r'(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*["\'](/[^"\']+)["\']', "Fetch/Axios call"),
    (r'(?:XMLHttpRequest|xhr).*?open\s*\(\s*["\'](\w+)["\'],\s*["\']([^"\']+)["\']', "XHR call"),
    (r'(?i)(graphql|gql)\s*["\']?\s*:\s*["\']([^"\']+)["\']', "GraphQL endpoint"),
    (r'new WebSocket\s*\(\s*["\']([^"\']+)["\']', "WebSocket endpoint"),
    (r'(?i)/api/(?:admin|internal|debug|v\d+)/[^\s"\']+', "API path"),
]


def scan_sinks(js_code: str) -> list[dict]:
    results = []
    for pattern, name, category in SINK_PATTERNS:
        for m in re.finditer(pattern, js_code):
            line_no = js_code[: m.start()].count("\n") + 1
            results.append({"name": name, "category": category, "line": line_no, "snippet": m.group(0)[:120]})
    return results


def scan_secrets(content: str) -> list[dict]:
    results = []
    seen = set()
    for pattern, name, severity in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            key = m.group(0)[:40]
            if key in seen:
                continue
            seen.add(key)
            line_no = content[: m.start()].count("\n") + 1
            results.append({"name": name, "severity": severity, "line": line_no, "snippet": m.group(0)[:80]})
    return results


def scan_role_logic(js_code: str) -> list[dict]:
    results = []
    for pattern, name in ROLE_PATTERNS:
        for m in re.finditer(pattern, js_code, re.IGNORECASE):
            line_no = js_code[: m.start()].count("\n") + 1
            results.append({"name": name, "line": line_no, "snippet": m.group(0)[:120]})
    return results


def scan_apis(content: str) -> list[dict]:
    results = []
    seen = set()
    for pattern, name in API_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            endpoint = m.group(1) if m.lastindex >= 1 else m.group(0)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            results.append({"name": name, "endpoint": endpoint, "snippet": m.group(0)[:120]})
    return results
