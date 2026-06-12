"""HTTP helpers used by the Crawler Agent and others."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

import httpx


def build_client(session) -> httpx.Client:
    return httpx.Client(
        cookies=session.cookies,
        headers={
            "User-Agent": "SSS-Scanner/1.0",
            **session.headers,
        },
        follow_redirects=True,
        timeout=15,
        verify=False,
    )


def is_in_scope(url: str, session) -> bool:
    parsed = urlparse(url)
    target = urlparse(session.target_url)
    if parsed.netloc and parsed.netloc != target.netloc:
        return False
    for excl in session.scope_exclude:
        if excl in url:
            return False
    return True


def extract_links(base_url: str, html: str) -> list[str]:
    pattern = re.compile(r'href=["\']([^"\'#?]+)["\']', re.IGNORECASE)
    links = []
    for m in pattern.finditer(html):
        href = m.group(1)
        full = urljoin(base_url, href)
        if urlparse(full).scheme in ("http", "https"):
            links.append(full)
    return list(set(links))


def extract_js_urls(base_url: str, html: str) -> list[str]:
    pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    urls = []
    for m in pattern.finditer(html):
        src = m.group(1)
        full = urljoin(base_url, src)
        if urlparse(full).scheme in ("http", "https"):
            urls.append(full)
    return list(set(urls))


def extract_api_hints(html: str, js: str) -> list[str]:
    combined = html + "\n" + js
    pattern = re.compile(
        r'(?:fetch|axios|xhr\.open)\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    return list({m.group(1) for m in pattern.finditer(combined)})
