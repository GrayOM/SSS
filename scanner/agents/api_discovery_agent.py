"""API Discovery Agent — finds all endpoints including hidden/admin APIs."""
from __future__ import annotations
import logging
import re

from scanner.models import AgentResult, CrawlResult, Finding, Severity
from scanner.tools.pattern_tools import scan_apis

log = logging.getLogger("api_discovery_agent")

ADMIN_KEYWORDS = ["admin", "internal", "debug", "superuser", "mgmt", "management", "sys", "backstage"]
SENSITIVE_METHODS = ["DELETE", "PUT", "PATCH"]


class ApiDiscoveryAgent:
    name = "API Discovery Agent"

    def run(self, crawl: CrawlResult) -> AgentResult:
        log.info("[API Discovery] Scanning for endpoints")
        result = AgentResult(agent_name=self.name)

        all_endpoints: list[dict] = []

        for url, content in {**crawl.js_contents, **crawl.page_contents}.items():
            for hit in scan_apis(content):
                hit["source_file"] = url
                all_endpoints.append(hit)

        # Deduplicate
        seen = set()
        unique: list[dict] = []
        for ep in all_endpoints:
            key = ep["endpoint"]
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        result.metadata["endpoints_discovered"] = unique

        for ep in unique:
            endpoint = ep["endpoint"]
            low = endpoint.lower()

            # Admin / internal API
            if any(kw in low for kw in ADMIN_KEYWORDS):
                result.findings.append(Finding(
                    title=f"Admin/Internal API Exposed in Client Code: {endpoint}",
                    severity=Severity.HIGH,
                    agent=self.name,
                    affected_resource=ep["source_file"],
                    evidence=f"Endpoint `{endpoint}` referenced in client-side resource `{ep['source_file']}`",
                    description="An administrative or internal API endpoint is referenced in client-accessible JavaScript. The endpoint may lack proper authorization.",
                    attack_scenario=f"Call `{endpoint}` directly → gain admin-level data or actions if authorization is missing.",
                    impact="Unauthorized admin actions; data breach.",
                    remediation="Ensure admin APIs are protected by server-side authorization. Remove from client bundles if not needed.",
                    confidence=0.75,
                    tags=["api", "admin", "hidden"],
                ))

            # GraphQL
            if "graphql" in low or "/gql" in low:
                result.findings.append(Finding(
                    title=f"GraphQL Endpoint Discovered: {endpoint}",
                    severity=Severity.MEDIUM,
                    agent=self.name,
                    affected_resource=ep["source_file"],
                    evidence=f"GraphQL endpoint `{endpoint}` found",
                    description="GraphQL endpoint discovered. Introspection or overly broad queries may expose the full data schema.",
                    attack_scenario="Send introspection query → enumerate all types/queries → harvest data via batched requests.",
                    impact="Schema exposure; unauthorized data access via crafted queries.",
                    remediation="Disable introspection in production. Implement query complexity limits and field-level authorization.",
                    confidence=0.8,
                    tags=["api", "graphql"],
                ))

        # WebSocket check
        all_code = "\n".join(list(crawl.js_contents.values()) + list(crawl.page_contents.values()))
        for m in re.finditer(r'new WebSocket\s*\(\s*["\']([^"\']+)["\']', all_code):
            ws_url = m.group(1)
            result.findings.append(Finding(
                title=f"WebSocket Endpoint: {ws_url}",
                severity=Severity.LOW,
                agent=self.name,
                affected_resource="JS",
                evidence=f"WebSocket connection to `{ws_url}`",
                description="WebSocket endpoint found. Verify authentication and message validation.",
                attack_scenario="Connect to WebSocket without authentication → receive real-time data.",
                impact="Depends on WebSocket message content — potential real-time data leakage.",
                remediation="Authenticate WebSocket upgrades. Validate all incoming messages server-side.",
                confidence=0.5,
                tags=["api", "websocket"],
            ))

        log.info("[API Discovery] %d findings, %d unique endpoints", len(result.findings), len(unique))
        return result
