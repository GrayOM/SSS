# AI 기반 JS/HTML 취약점 분석 준비 도구

## 프로젝트 개요
로컬 실행형 JS/HTML 취약점 분석 준비 도구입니다.
ZIP 업로드 기반 전처리 파이프라인을 통해 분석 대상 파일 목록을 생성하고, 이후 AI 분석 모듈이 사용할 입력을 준비합니다.

## 처리 흐름
ZIP 업로드 → 보안 검증 → 압축 해제 → 파일 필터링 → 분석 대상 목록 반환

## 지원 및 제외 정책
### 포함 확장자
- `.js`, `.html`, `.json`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.ejs`, `.hbs`, `.pug`

### 포함 파일
- `package.json`
- `Dockerfile`
- `docker-compose.yml`
- `docker-compose.yaml`

### 허용 env 샘플
- `.env.example`
- `.env.sample`

### 제외 규칙
- 실제 `.env` 파일은 분석 대상에서 제외
- 제외 경로: `node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`, `__pycache__`, `libs`, `cdn`
- 제외 파일: `*.min.js`, `*.bundle.js`, `*.chunk.js`, `bundle.js`, webpack build output

### 예시
- `jquery-custom-validation.js`는 포함
- `jquery.min.js`는 제외

## ZIP 보안 정책
- ZIP Slip 방어
- ZIP MIME Type 검증(`application/zip`, `application/x-zip-compressed`, `multipart/x-zip`, 유효한 ZIP 시그니처의 `application/octet-stream`)
- ZIP 멤버 수 제한
- 압축 해제 총 용량 제한
- symlink 차단
- 업로드 용량 제한(기본 20MB)

## 분석 결과 저장
- 완료된 `/api/analyze` 결과는 SQLite에 저장됩니다.
- DB 경로는 `ANALYSIS_DB_PATH` 환경 변수로 설정합니다.
- 조회 API: `GET /api/analysis-runs`, `GET /api/analysis-runs/{run_id}`
- 저장 JSON은 API 응답용 안전 결과만 포함하며 원본 파일 `content` 필드는 저장하지 않습니다.

## Docker 보안 정책
- non-root(`appuser`) 실행
- `127.0.0.1:8000:8000` localhost 바인딩
- `/tmp/ai_code_analyzer` tmpfs 사용
- 전체 volume mount 없음

## 요구 환경
- Python 3.9 이상

## 로컬 실행 방법
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## Docker 실행 방법
```bash
cp .env.example .env
docker compose build
docker compose up
```

## 테스트 실행 방법
```bash
make test
# 또는
python -m pytest tests/ -v
```

## 향후 AI 분석 모듈 예정 구조
- `app/services/file_content_loader.py`
- `app/services/chunk_service.py`
- `app/services/analysis_service.py`
- `app/services/report_service.py`
