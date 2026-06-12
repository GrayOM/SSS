# SSS — AI Source Vulnerability Analyzer

AI 기반 웹 애플리케이션 소스코드 보안 취약점 분석 도구.  
ZIP 파일을 업로드하면 JS/HTML 소스를 자동 분석하고, 브라우저 콘솔에서 즉시 실행 가능한 PoC 코드와 함께 취약점 보고서를 생성합니다.

---

## Features

- **ZIP 업로드 기반 분석** — JS, HTML, TypeScript, Vue 등 프론트엔드 소스 자동 필터링
- **Source Intelligence Manifest** — 프레임워크 탐지, 라우트/API/폼/핸들러 구조를 라인 번호 포함 추출
- **멀티 에이전트 AI 분석** — Gemini / Claude / OpenAI 백엔드 선택 가능
- **브라우저 콘솔 PoC 생성** — 실제 세션에서 바로 붙여넣기 가능한 검증 코드 출력
- **Finding 생명주기** — raw signal → review candidate → runtime verification candidate → confirmed finding
- **SQLite 결과 저장** — 분석 이력 조회 API 포함
- **ZIP 보안 정책** — ZIP Slip 방어, 심볼릭 링크 차단, 압축 해제 용량 제한

---

## Requirements

- Python 3.9 이상
- AI API Key (아래 참조)

---

## Quick Start

### 1. 저장소 클론

```bash
git clone https://github.com/<your-username>/SSS.git
cd SSS
```

### 2. 가상환경 및 의존성 설치

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. 환경 설정

```bash
cp .env.example .env
```

`.env` 파일을 열어 API Key를 입력합니다 (아래 [Environment Variables](#environment-variables) 참조).

### 4. 서버 실행

```bash
uvicorn app.main:app --reload
```

브라우저에서 **http://localhost:8000** 접속 후 ZIP 파일을 업로드하세요.

---

## Docker 실행

```bash
cp .env.example .env
# .env 에 API Key 입력

docker compose build
docker compose up
```

서버: **http://localhost:8000**

---

## API Key 설정

분석 백엔드는 `.env`의 `ANALYZER_BACKEND` 값으로 선택합니다.

### Gemini (기본값 권장)

1. [Google AI Studio](https://aistudio.google.com/app/apikey) 접속
2. **Create API Key** 클릭
3. 발급된 키를 `.env`에 입력:
   ```
   ANALYZER_BACKEND=gemini
   POC_BACKEND=gemini
   GEMINI_API_KEY=AIzaSy...
   GEMINI_MODEL=gemini-2.5-flash-lite
   ```

### Claude (Anthropic)

1. [console.anthropic.com](https://console.anthropic.com) 접속
2. **API Keys → Create Key**
3. `.env` 설정:
   ```
   ANALYZER_BACKEND=gemini   # 현재 claude 백엔드는 gemini 클라이언트 경유
   ANTHROPIC_API_KEY=sk-ant-...
   CLAUDE_MODEL=claude-sonnet-4-6
   ```

### OpenAI

1. [platform.openai.com/api-keys](https://platform.openai.com/api-keys) 접속
2. **Create new secret key**
3. `.env` 설정:
   ```
   OPENAI_API_KEY=sk-...
   OPENAI_MODEL=gpt-4o-mini
   ```

### 테스트 모드 (API Key 없이)

```
ANALYZER_BACKEND=mock
POC_BACKEND=mock
```

패턴 기반 분석 결과를 반환합니다. 실제 AI 호출 없이 파이프라인 동작을 확인할 수 있습니다.

---

## Environment Variables

| 변수 | 필수 | 설명 |
|------|------|------|
| `ANALYZER_BACKEND` | No | `mock` (기본) 또는 `gemini` |
| `POC_BACKEND` | No | `mock` (기본) 또는 `gemini` |
| `GEMINI_API_KEY` | Gemini 사용 시 | Google AI API Key |
| `GEMINI_MODEL` | No | 기본: `gemini-2.5-flash-lite` |
| `ANTHROPIC_API_KEY` | Claude 사용 시 | Anthropic API Key |
| `CLAUDE_MODEL` | No | 기본: `claude-3-5-sonnet-latest` |
| `OPENAI_API_KEY` | OpenAI 사용 시 | OpenAI API Key |
| `OPENAI_MODEL` | No | 기본: `gpt-5-mini` |
| `MAX_UPLOAD_SIZE_MB` | No | 업로드 최대 용량 (기본: `20`) |
| `MAX_CHUNK_LINES` | No | 청크 분할 라인 수 (기본: `200`) |
| `ANALYSIS_DB_PATH` | No | SQLite 저장 경로 (기본: `/tmp/ai_code_analyzer/analysis_runs.sqlite3`) |

---

## Usage

### 분석 실행

1. **http://localhost:8000** 접속
2. 분석 대상 프로젝트를 ZIP으로 압축 후 업로드
3. 분석 완료 후 결과 확인:
   - **Executive Findings** — 점수 ≥ 5, PoC 포함된 확인된 취약점
   - **Review Candidates** — 수동 검토 필요 항목
   - **Common Console Helper** — 브라우저 인터셉터 공통 코드

### API 직접 호출

```bash
# 분석 요청
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@your-project.zip"

# 분석 이력 조회
curl http://localhost:8000/api/analysis-runs

# 특정 결과 조회
curl http://localhost:8000/api/analysis-runs/{run_id}
```

### 지원 파일 형식

포함: `.js` `.html` `.json` `.mjs` `.cjs` `.ts` `.jsx` `.tsx` `.vue` `.ejs` `.hbs` `.pug`  
제외: `node_modules/`, `dist/`, `*.min.js`, webpack 빌드 산출물

---

## 테스트 실행

```bash
# 전체 테스트
make test

# 또는
python -m pytest tests/ -v

# 단일 파일
python -m pytest tests/test_console_poc_analysis_service.py -v

# 단일 케이스
python -m pytest tests/test_analysis_service.py::test_name -v
```

---

## Architecture

```
ZIP Upload
  → upload_service      (MIME, ZIP Slip, 크기, 심볼릭 링크 검증)
  → scan_service        (확장자/경로 필터링)
  → file_content_loader (허용 파일 읽기)
  → chunk_service       (CodeChunk[] 분할, overlap 포함)
  → analysis_service    (MockAnalyzer or GeminiAnalyzer)
  → console_poc_analysis_service  (promotion scoring, PoC 생성)
  → analysis_run_repository       (SQLite 저장)
  → FullAnalysisResponse          (content 필드 제거 후 반환)
```

---

## 주의사항

- **`.env` 파일은 절대 커밋하지 마세요** — API Key가 포함됩니다 (`.gitignore`에 등록됨)
- 분석 대상은 본인이 권한을 보유한 소스코드만 사용하세요
- SQLite DB(`*.sqlite3`)는 gitignore 처리되어 있습니다

---

## License

MIT
