#!/usr/bin/env python3
"""Build a non-vendored public-pattern corpus summary for SSS.

The script inspects public repositories cloned under .external_corpus/ and
writes derived metadata only. It intentionally does not copy third-party source
files into the SSS repository.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / ".external_corpus"
DOC = ROOT / "docs" / "generalization_corpus.md"
JSON_OUT = ROOT / "docs" / "generalization_corpus.json"

SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".hbs", ".ejs", ".pug"}
MAX_BYTES = 750_000

PATTERNS: dict[str, str] = {
    "fetch": r"\bfetch\s*\(",
    "axios": r"\baxios\.(?:get|post|put|patch|delete)\s*\(",
    "angular_httpclient": r"\b(?:this\.)?http\.(?:get|post|put|patch|delete)\s*\(",
    "jquery_ajax": r"\b(?:\$|jQuery)\.ajax\s*\(",
    "api_client_wrapper": r"\b(?:api|apiClient|httpClient|client|request)\.(?:get|post|put|patch|delete|request)\s*\(",
    "html_form_action": r"<form\b[^>]*\baction\s*=",
    "react_event": r"\bon(?:Click|Submit|Change)\s*=\s*\{",
    "vue_event": r"(?:@|v-on:)(?:click|submit|change)",
    "jquery_event": r"\.on\(\s*['\"](?:click|submit|change)['\"]",
    "dom_listener": r"\baddEventListener\(\s*['\"](?:click|submit|change|message)['\"]",
    "formdata": r"\bFormData\s*\(|\.append\(\s*['\"]",
    "urlsearchparams": r"\bURLSearchParams\s*\(",
    "dom_source": r"\b(?:location\.hash|location\.search|document\.URL|window\.name|event\.data)\b",
    "dom_sink": r"(?:\.innerHTML\b|\bdocument\.write\s*\(|\beval\s*\(|\bpostMessage\s*\()",
    "storage": r"\b(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(",
    "route_param": r"(?:path\s*:\s*['\"][^'\"]*:[A-Za-z_][A-Za-z0-9_]*|/:[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_.]*\})",
}

LICENSE_HINTS = {
    "juice-shop": "MIT license in repository metadata/source headers",
    "nodegoat": "OWASP intentionally vulnerable training application; inspect repository license before redistributing source",
}


def iter_files(repo: Path):
    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        parts = {p.lower() for p in path.parts}
        if {".git", "node_modules", "dist", "build", "coverage"} & parts:
            continue
        if path.stat().st_size > MAX_BYTES:
            continue
        yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def inspect_repo(repo: Path) -> dict:
    counts: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    file_count = 0
    for path in iter_files(repo):
        text = read_text(path)
        if not text:
            continue
        file_count += 1
        rel = str(path.relative_to(repo)).replace("\\", "/")
        for name, pattern in PATTERNS.items():
            if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                counts[name] += 1
                if len(examples[name]) < 5:
                    examples[name].append(rel)
    return {
        "name": repo.name,
        "path": str(repo.relative_to(ROOT)),
        "license_note": LICENSE_HINTS.get(repo.name, "Public repository; verify license before redistributing source"),
        "source_files_inspected": file_count,
        "pattern_counts": dict(sorted(counts.items())),
        "example_files": dict(sorted(examples.items())),
    }


def write_docs(summary: dict) -> None:
    lines: list[str] = [
        "# SSS Generalization Corpus",
        "",
        "This corpus is engineering metadata, not a trained model and not a vendored copy of public projects.",
        "External repositories are cloned under `.external_corpus/`, which is ignored by git.",
        "Only derived pattern counts, representative fixture names, and support notes are stored here.",
        "",
        "## Sources Inspected",
        "",
    ]
    for repo in summary["repositories"]:
        lines.extend([
            f"### {repo['name']}",
            "",
            f"- Local path: `{repo['path']}`",
            f"- License note: {repo['license_note']}",
            f"- Source-like files inspected: {repo['source_files_inspected']}",
            "- Pattern counts:",
        ])
        if repo["pattern_counts"]:
            for name, count in repo["pattern_counts"].items():
                lines.append(f"  - `{name}`: {count}")
        else:
            lines.append("  - none detected")
        lines.append("- Example files by pattern:")
        for name, files in repo["example_files"].items():
            joined = ", ".join(f"`{x}`" for x in files)
            lines.append(f"  - `{name}`: {joined}")
        lines.append("")

    lines.extend([
        "## Pattern Taxonomy",
        "",
        "- API calls: fetch, axios, Angular HttpClient, jQuery ajax, object-style wrappers, named api/client wrappers.",
        "- Endpoint construction: literals, base URL aliases, template route params, concatenated aliases, HTML form actions.",
        "- UI mapping: React handlers, Vue handlers, jQuery `.on`, DOM `addEventListener`, form submit buttons.",
        "- Payloads: inline objects, payload variables, FormData append, URLSearchParams append, form input names.",
        "- Browser proof targets: payment/order mutations, wallet/value mutations, ID route params, account recovery, DOM XSS, storage/auth branches.",
        "- Noise: session/init/search/recommendation, analytics/static assets, vendor/minified/runtime code.",
        "",
        "## Derived Fixtures",
        "",
        "- `scripts/verify_generalization.py` contains minimal derived snippets for Angular HttpClient, HTML form actions, API wrappers, FormData, URLSearchParams, DOM XSS, storage auth, and noise/destructive cases.",
        "- `scripts/verify_realistic_output.py` contains product-direction fixtures for payment, auction, wallet, Iamport, Stripe, recovery, login, route params, and destructive endpoints.",
        "",
        "## Supported Patterns",
        "",
        "- Direct helper-free promoted API PoCs for concrete fetch/axios/jQuery/wrapper/Angular HttpClient calls.",
        "- Editable route constants for stable route params.",
        "- Base URL normalization for common and alias-derived paths.",
        "- Manual demotion for uncertain wrappers, destructive endpoints, build artifacts, and generic/noisy GETs.",
        "- DOM source/sink and storage/auth branch extraction with browser-console-oriented proof output.",
        "",
        "## Unsupported Or Future Work",
        "",
        "- Full inter-file call graph from component method to injected service method is still heuristic.",
        "- Complex Angular observable pipelines and generated OpenAPI clients need richer parsing.",
        "- Server-rendered forms can be extracted, but browser-verifiable promotion remains conservative when no handler context exists.",
        "- Dynamic endpoint builders with non-literal route fragments still require manual Network-tab validation.",
    ])
    DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    repos = [p for p in sorted(EXTERNAL.iterdir()) if p.is_dir()] if EXTERNAL.exists() else []
    summary = {
        "external_corpus_path": str(EXTERNAL.relative_to(ROOT)),
        "repository_count": len(repos),
        "repositories": [inspect_repo(repo) for repo in repos],
    }
    JSON_OUT.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    write_docs(summary)
    print(f"generalization_corpus: repositories={len(repos)}")
    for repo in summary["repositories"]:
        print(f"  {repo['name']}: files={repo['source_files_inspected']} patterns={sum(repo['pattern_counts'].values())}")
    print(f"wrote {DOC.relative_to(ROOT)}")
    print(f"wrote {JSON_OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
