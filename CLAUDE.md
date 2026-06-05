# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## SSS Project Goal

Source-code analysis -> review candidates -> short PoC generation -> browser console verification -> confirmed findings -> report output.

## Rules

- Never mix review candidates with confirmed findings.
- A finding is confirmed only after concrete evidence and verification.
- Browser-console PoCs must be short, pasteable, and finding-specific.
- Do not duplicate large helper code inside every PoC.
- `common_console_helper` (`_build_common_console_helper`) contains reusable browser interception logic; finding-specific PoCs call its API (`window.SSS_POC.*`) rather than re-implementing transport hooks.
- Do not run `git add`, `commit`, `push`, or `merge` unless explicitly asked.
- Before editing, inspect `git status`.
- After editing, summarize changed files and tests.
- Do not weaken security restrictions or tests to make them pass - fix the root cause.
- Do not leave sample nicknames (`ebs`, `nls`, `cia`, `nafal`, etc.) in fixtures, tests, or docs.
- Always open files with `encoding="utf-8"` (Windows compatibility).

## Commands

```bash
# Run all tests
make test
# or
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_console_poc_analysis_service.py -v

# Run a single test by name
python -m pytest tests/test_analysis_service.py::test_name -v

# Start the dev server (local venv)
source .venv/bin/activate
uvicorn app.main:app --reload

# Docker
docker compose build && docker compose up
```

## Architecture

### Pipeline (per `/api/analyze` request)

```
ZIP upload
  -> prepare_uploaded_zip        (upload_service: MIME, ZIP Slip, size, symlink checks)
  -> scan_extracted_directory    (scan_service: extension/path allowlist filtering)
  -> load_file_contents          (file_content_loader: reads allowed files as FileContent[])
  -> build_chunks                (chunk_service: splits files into CodeChunk[] with overlap)
  -> analyze_chunks              (analysis_service: MockAnalyzer or GeminiAnalyzer per chunk)
  -> analyze_console_exploitability  (console_poc_analysis_service: produces ReadableFinding[])
  -> save_analysis_run           (analysis_run_repository: persists to SQLite)
  -> FullAnalysisResponse        (response_mapper: strips raw content before JSON return)
```

### Two parallel analysis paths

| Path | Service | Output | Purpose |
|---|---|---|---|
| Chunk analyzer | `analysis_service.py` | `VulnerabilityFinding[]` | Pattern/Gemini per-chunk findings |
| Console PoC analyzer | `console_poc_analysis_service.py` | `ReadableFinding[]` | Browser-console-oriented, promotion-scored |

`readable_analysis` (console PoC path) is the primary output for security diagnostics; `analysis` (chunk path) is legacy.

### Key service files

- `source_intelligence.py` - builds `ProjectUnderstandingResult` (framework detection, route/page/API manifest, risk categorization)
- `api_candidate_extractor.py` - extracts `ApiCallCandidate[]` and `UiEventCandidate[]` from JS/HTML source
- `console_poc_analysis_service.py` - promotion scoring, `_build_common_console_helper`, `_build_network_hook_mutation_poc`, `_build_short_console_verification_code`; also contains `MockConsolePocAnalyzer` and `GeminiConsolePocAnalyzer`
- `poc_templates.py` - reusable PoC template builders (`build_dom_xss_poc`, `build_storage_auth_poc`, `build_request_replay_poc`)
- `prompt_builder.py` - constructs Gemini prompts for both chunk analysis and console PoC analysis
- `response_mapper.py` - strips `content` fields before saving/returning

### Analyzer backends (configurable via `.env`)

```
ANALYZER_BACKEND=mock    # default: pattern-based MockAnalyzer
ANALYZER_BACKEND=gemini  # GeminiAnalyzer via google-genai

POC_BACKEND=mock         # default: MockPocGenerator
POC_BACKEND=gemini       # GeminiPocGenerator

GEMINI_API_KEY=...
GEMINI_MODEL=gemini-2.5-flash-lite   # default
```

### PoC safety contract

- `_is_allowed_guarded_poc_code` enforces the guard policy: mutation PoCs must contain `sss_poc_state`/`sss_review_poc_state` with `armMutation`/`disarm`, or a `confirm()`-gated guard. DELETE/refund/transfer endpoints are always blocked.
- `UNRESOLVED_POC_PLACEHOLDERS` - findings with unresolved placeholders (`{API_BASE_URL}`, `{userId}`, etc.) are downgraded to manual review candidates, not promoted findings.
- `PROMOTION_SCORE_THRESHOLD = 5` - findings below this score stay as review candidates.

### Finding states

1. **Review candidate** - title prefixed `"Manual review candidate:"`, needs runtime capture
2. **Promoted finding** - score >= 5, concrete endpoint/page/action resolved, observational PoC attached

### API surface

| Route | Purpose |
|---|---|
| `POST /api/analyze` | Main analysis entry point (ZIP upload) |
| `GET /api/analysis-runs` | List past analysis runs |
| `GET /api/analysis-runs/{run_id}` | Single run detail |
| `GET /` | SPA UI (`app/templates/index.html`) |

### ZIP security policy

ZIP Slip defense, MIME type validation, member count limit (`MAX_ZIP_MEMBERS=5000`), uncompressed size limit (`MAX_UNCOMPRESSED_SIZE_MB=200`), symlink blocking, upload size limit (`MAX_UPLOAD_SIZE_MB=20`). These limits must not be weakened.

### File inclusion policy

Allowed: `.js .html .json .mjs .cjs .ts .jsx .tsx .vue .ejs .hbs .pug`, plus `package.json`, `Dockerfile`, `docker-compose.yml`, `.env.example`/`.env.sample`.
Excluded: `node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`, `__pycache__`, `libs`, `cdn`, `*.min.js`, `*.bundle.js`, `*.chunk.js`, webpack build output, actual `.env` files.

### SQLite persistence

Analysis results are stored at `ANALYSIS_DB_PATH` (default `/tmp/ai_code_analyzer/analysis_runs.sqlite3`). Raw file `content` fields are never persisted.
