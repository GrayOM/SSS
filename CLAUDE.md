# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Claude Code Workflow Role

Claude Code is used as the architecture and usability reviewer for this repository.

### Primary Responsibilities

- Perform architecture review for proposed or completed changes.
- Perform real usability review from the perspective of a security assessor using the tool.
- Identify concrete files, functions, and tests that Codex should modify.
- Write the final review output to `docs/AI_REVIEW.md`.
- Call out push blockers clearly.

### Review Output

Claude Code should fill `docs/AI_REVIEW.md` using this structure:

- Critical Issues
- Implementation Recommendations
- Files Codex Should Modify
- Tests Codex Should Add
- Push Blockers

### Boundaries

- Do not edit files unless explicitly asked.
- Do not run `git add`, `git commit`, `git push`, or `git merge`.
- Do not weaken tests or recommend weakening tests to pass.
- Do not remove PoC requirements or security controls.

### Collaboration With Codex

Claude Code should produce a review that Codex can implement directly. Prefer specific file paths, function names, expected behavior, and test names over broad descriptions.

---

## Commands

```bash
# Local development
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload

# Docker
docker compose build && docker compose up

# Tests
make test
python -m pytest tests/ -v

# Single test
python -m pytest tests/test_console_poc_analysis_service.py::TestClass::test_name -v
```

## Architecture

### Analysis Pipeline

`POST /api/analyze` (ZIP upload) runs through these stages in sequence - each wraps a distinct service:

1. **Upload & extraction** - `upload_service.py` + `zip_service.py`: validates MIME, ZIP Slip, member count, size, symlinks; unpacks to tmpfs workspace.
2. **File scan** - `scan_service.py` -> `file_filter_service.py`: applies extension allowlist (`.js`, `.html`, `.ts`, `.vue`, etc.) and path exclusions (`node_modules`, `dist`, `*.min.js`, webpack hashes, etc.).
3. **Content load** - `file_content_loader.py`: reads included files with `encoding="utf-8"`.
4. **Chunking** - `chunk_service.py`: splits each file into 200-line chunks with 20-line overlap (configurable via `MAX_CHUNK_LINES` / `CHUNK_OVERLAP_LINES`).
5. **Legacy analysis** - `analysis_service.py`: per-chunk pattern analysis; returns `AnalysisResult` with `VulnerabilityFinding` items. Backend selected by `ANALYZER_BACKEND` env var (`mock` or `gemini`).
6. **Console PoC analysis** - `console_poc_analysis_service.py`: produces `ReadableAnalysisResult` with `ReadableFinding`, `ConsoleVerificationPlaybook`, and generated PoC code. Backend selected by `POC_BACKEND` env var. This is the primary output consumed by the UI.
7. **Safe response** - `response_mapper.py`: strips raw file `content` before API response.
8. **Persistence** - `analysis_run_repository.py`: saves result to SQLite (`ANALYSIS_DB_PATH`).

The `FullAnalysisResponse` schema in `app/models/schemas.py` is the single source of truth for the API contract.

### Two Analyzer Backends

- `MockAnalyzer` / `MockConsolePocAnalyzer`: pattern-matching fallback; used in tests and when no API key is configured.
- `GeminiAnalyzer` / `GeminiConsolePocAnalyzer`: calls Gemini API; requires `GEMINI_API_KEY` and `ANALYZER_BACKEND=gemini` / `POC_BACKEND=gemini`.

OpenAI and Claude backends are defined in config but **not yet implemented** (`get_analyzer()` raises `ValueError` for unknown backends).

### Source Intelligence Layer

`source_intelligence.py` builds a `ProjectUnderstandingResult` (framework hint, route map, API inventory, UI event candidates) used by `console_poc_analysis_service.py` to generate context-aware PoC code. `api_candidate_extractor.py` feeds raw API-call and UI-handler candidates into this layer.

### PoC Safety Rules

- All generated PoC code that makes network requests must include an `SSS_POC_STATE` guard (`mutationArmed / armMutation / disarm` pattern) or equivalent - see `_is_allowed_guarded_poc_code()` in `console_poc_analysis_service.py`.
- Destructive endpoints (`delete`, `refund`, `withdraw`, `transfer`, `bulk`) are blocked from replay via `BLOCKED_REPLAY` flag.
- PoC fallback order: executable PoC -> `observational_poc` -> `manual_poc_plan` + reason.

### Key Config (`app/core/config.py`)

All settings load from `.env` via `pydantic-settings`. Defaults use `mock` backends, so the app runs without API keys.

| Variable | Default | Purpose |
|---|---|---|
| `ANALYZER_BACKEND` | `mock` | `mock` or `gemini` |
| `POC_BACKEND` | `mock` | `mock` or `gemini` |
| `GEMINI_API_KEY` | (none) | Required for `gemini` backend |
| `ANALYSIS_DB_PATH` | `/tmp/...` | SQLite path |
| `MAX_UPLOAD_SIZE_MB` | `20` | ZIP upload limit |

## Development Rules (from AGENTS.md)

- Never weaken security controls or file upload restrictions to pass tests - fix the root cause.
- Do not use sample nicknames (`ebs`, `nls`, `cia`, `nafal`) in fixture or test data.
- All file reads must specify `encoding="utf-8"` (Windows compatibility).
- `_is_build_or_third_party_path()` guards must be preserved to avoid false positives on minified/vendor code.
