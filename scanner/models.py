"""Shared data models for all scanner agents."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class ScanSession:
    """Authenticated session context passed to all agents."""
    target_url: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    role: str = "user"


@dataclass
class CrawlResult:
    """Output from Crawler Agent."""
    pages: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    css_files: list[str] = field(default_factory=list)
    api_hints: list[str] = field(default_factory=list)
    sourcemaps: list[str] = field(default_factory=list)
    robots_txt: Optional[str] = None
    sitemap_xml: Optional[str] = None
    page_contents: dict[str, str] = field(default_factory=dict)
    js_contents: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    """Single security finding from any agent."""
    title: str
    severity: Severity
    agent: str
    affected_resource: str
    evidence: str
    description: str
    attack_scenario: str = ""
    impact: str = ""
    remediation: str = ""
    confidence: float = 0.5
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class AgentResult:
    """Structured output returned by every specialist agent."""
    agent_name: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
