"""Crawler Agent — builds complete site map and asset inventory."""
from __future__ import annotations
import logging
from collections import deque
from urllib.parse import urljoin, urlparse

from scanner.models import AgentResult, CrawlResult, ScanSession
from scanner.tools.http_tools import (
    build_client,
    extract_api_hints,
    extract_js_urls,
    extract_links,
    is_in_scope,
)

log = logging.getLogger("crawler_agent")
MAX_PAGES = 100


class CrawlerAgent:
    name = "Crawler Agent"

    def run(self, session: ScanSession) -> tuple[CrawlResult, AgentResult]:
        log.info("[Crawler] Starting crawl: %s", session.target_url)
        result = AgentResult(agent_name=self.name)
        crawl = CrawlResult()

        client = build_client(session)

        # robots.txt
        try:
            r = client.get(urljoin(session.target_url, "/robots.txt"))
            if r.status_code == 200:
                crawl.robots_txt = r.text
                log.info("[Crawler] robots.txt fetched (%d bytes)", len(r.text))
        except Exception as e:
            result.errors.append(f"robots.txt: {e}")

        # sitemap.xml
        try:
            r = client.get(urljoin(session.target_url, "/sitemap.xml"))
            if r.status_code == 200:
                crawl.sitemap_xml = r.text
                log.info("[Crawler] sitemap.xml fetched (%d bytes)", len(r.text))
        except Exception as e:
            result.errors.append(f"sitemap.xml: {e}")

        # BFS crawl
        queue: deque[str] = deque([session.target_url])
        visited: set[str] = set()

        while queue and len(visited) < MAX_PAGES:
            url = queue.popleft()
            if url in visited:
                continue
            if not is_in_scope(url, session):
                continue
            visited.add(url)

            try:
                resp = client.get(url)
                html = resp.text
                crawl.pages.append(url)
                crawl.page_contents[url] = html
                log.info("[Crawler] page %s (%d bytes)", url, len(html))
            except Exception as e:
                result.errors.append(f"GET {url}: {e}")
                continue

            # JS files
            for js_url in extract_js_urls(url, html):
                if js_url not in crawl.js_files:
                    crawl.js_files.append(js_url)
                    try:
                        jr = client.get(js_url)
                        crawl.js_contents[js_url] = jr.text
                    except Exception as e:
                        result.errors.append(f"JS {js_url}: {e}")

            # SourceMaps
            for js_url in crawl.js_files:
                sm_url = js_url + ".map"
                if sm_url not in crawl.sourcemaps:
                    try:
                        sr = client.get(sm_url)
                        if sr.status_code == 200 and "sources" in sr.text:
                            crawl.sourcemaps.append(sm_url)
                            log.info("[Crawler] SourceMap found: %s", sm_url)
                    except Exception:
                        pass

            # API hints
            all_js = "\n".join(crawl.js_contents.values())
            for hint in extract_api_hints(html, all_js):
                if hint not in crawl.api_hints:
                    crawl.api_hints.append(hint)

            # Enqueue new links
            for link in extract_links(url, html):
                if link not in visited:
                    queue.append(link)

        result.metadata = {
            "pages_found": len(crawl.pages),
            "js_files_found": len(crawl.js_files),
            "sourcemaps_found": len(crawl.sourcemaps),
            "api_hints_found": len(crawl.api_hints),
        }
        log.info("[Crawler] Done — %d pages, %d JS files", len(crawl.pages), len(crawl.js_files))
        return crawl, result
