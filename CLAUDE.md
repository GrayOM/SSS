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

# AI fix loop (automated test-fix cycle, max 3 rounds; human reviews final diff)
./scripts/ai_fix_loop.sh         # Linux/macOS
./scripts/ai_fix_loop.ps1        # Windows
```

## Architecture

### API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | UI (Jinja2 template) |
| `POST` | `/api/upload` | File scan only - returns filtered file list, no analysis |
| `POST` | `/api/analyze` | Full pipeline (upload -> scan -> chunk -> analyze -> PoC -> persist) |
| `GET` | `/api/analysis-runs` | List saved runs from SQLite |
| `GET` | `/api/analysis-runs/{run_id}` | Retrieve a single saved run |

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

`ai_clients.py` provides `GeminiClient` and `GeminiClientProtocol` (the testable interface); inject `GeminiClientProtocol` rather than constructing `GeminiClient` directly in tests.

### Source Intelligence Layer

`source_intelligence.py` builds a `ProjectUnderstandingResult` (framework hint, route map, API inventory, UI event candidates) used by `console_poc_analysis_service.py` to generate context-aware PoC code. `api_candidate_extractor.py` feeds raw API-call and UI-handler candidates into this layer.

### PoC Systems

There are two separate PoC systems:

**`poc_templates.py`** (primary, used by `console_poc_analysis_service.py`): Typed, self-contained PoC builders that produce JavaScript pasteable directly into browser DevTools Console. Functions: `build_dom_xss_poc`, `build_storage_auth_poc`, `build_request_replay_poc`. Key constants: `MAX_POC_LINES = 12`, `INTERCEPTOR_SIGS` (patterns that must never appear in output), `is_interceptor_free()`. All output is ASCII-only and must pass `_is_allowed_guarded_poc_code()`.

**`poc_service.py`** (legacy): `GeminiPocGenerator` / `MockPocGenerator` for per-`VulnerabilityFinding` PoC generation. Invoked from the legacy analysis path.

### PoC Safety Rules

- All generated PoC code that makes network requests must include an `SSS_POC_STATE` guard (`mutationArmed / armMutation / disarm` pattern) or equivalent - see `_is_allowed_guarded_poc_code()` in `console_poc_analysis_service.py`.
- Destructive endpoints (`delete`, `refund`, `withdraw`, `transfer`, `bulk`) are blocked from replay via `BLOCKED_REPLAY` flag.
- PoC fallback order: executable PoC -> `observational_poc` -> `manual_poc_plan` + reason.
- `INTERCEPTOR_SIGS` in `poc_templates.py` lists global hook installers that must never appear in PoC output.

### Prompt Injection Defense

`prompt_builder.py` HTML-escapes all source code via `html.escape()` and wraps it in `<source_code>` tags. The prompt explicitly instructs the model to treat content inside those tags as data only. This invariant must not be removed or weakened.

### Quality & Evaluation Layer

- `analysis_quality_evaluator.py`: scores analysis results against measurable criteria (endpoint resolution, PoC generation rate, generic hint rate, etc.).
- `corpus_learning_service.py`: wraps quality results into generalization reports identifying common failure patterns (e.g. `endpoint_unknown`, `missing_poc_code`) and suggesting rules to improve - not model fine-tuning.
- `json_utils.py`: `extract_json_payload()` - robustly extracts JSON from AI responses that may include markdown fences or preamble text.

### Key Config (`app/core/config.py`)

All settings load from `.env` via `pydantic-settings`. Defaults use `mock` backends, so the app runs without API keys.

| Variable | Default | Purpose |
|---|---|---|
| `ANALYZER_BACKEND` | `mock` | `mock` or `gemini` |
| `POC_BACKEND` | `mock` | `mock` or `gemini` |
| `GEMINI_API_KEY` | (none) | Required for `gemini` backend |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model name |
| `ANALYSIS_DB_PATH` | `/tmp/...` | SQLite path |
| `TMP_DIR` | `/tmp/ai_code_analyzer` | Workspace for ZIP extraction |
| `MAX_UPLOAD_SIZE_MB` | `20` | ZIP upload limit |
| `MAX_FILE_SIZE_BYTES` | `2097152` | Per-file size limit (2 MB) |
| `MAX_ZIP_MEMBERS` | `5000` | Max files in a ZIP |
| `MAX_UNCOMPRESSED_SIZE_MB` | `200` | Max total uncompressed size |
| `MAX_CHUNK_LINES` | `200` | Lines per chunk |
| `CHUNK_OVERLAP_LINES` | `20` | Overlap between consecutive chunks |

## Development Rules (from AGENTS.md)

- Never weaken security controls or file upload restrictions to pass tests - fix the root cause.
- Do not use sample nicknames (`ebs`, `nls`, `cia`, `nafal`) in fixture or test data.
- All file reads must specify `encoding="utf-8"` (Windows compatibility).
- `_is_build_or_third_party_path()` guards must be preserved to avoid false positives on minified/vendor code.
- The AI fix loop (`ai_fix_loop.sh`) must not auto-merge to main; human review of the final diff is mandatory.
