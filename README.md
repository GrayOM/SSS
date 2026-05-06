# AI 기반 JS/HTML 취약점 분석 업로드 전처리 도구 (2차 안정화)

## 현재 범위
- ZIP 업로드
- 안전한 압축 해제
- 분석 대상 파일 필터링
- 결과 JSON 반환
- Docker 기반 로컬 실행

> AI 분석(Claude/OpenAI API) 모듈은 아직 구현하지 않음.

## 폴더 구조

# AI 기반 JS + HTML 소스코드 취약점 분석 준비 도구 (2차 개선)

## 개요
ZIP 업로드/압축해제/파일 선별 파이프라인을 보안적으로 강화했습니다.
AI 연동은 아직 포함하지 않으며, 이후 `analysis_service.py`를 추가하기 쉬운 구조로 분리했습니다.

## 변경된 폴더 구조
# AI 기반 JS + HTML 소스코드 취약점 분석 준비 도구 (1차)

## 개요
로컬에서 실행되는 FastAPI 웹 애플리케이션입니다.
사용자가 ZIP 파일을 업로드하면 서버가 안전하게 압축을 해제하고,
분석 대상 파일을 선별하여 JSON으로 반환합니다.

## 폴더 구조

```
.
├── app
│   ├── api
│   │   ├── routes_ui.py
│   │   └── routes_upload.py
│   │   └── routes.py
│   ├── core
│   │   └── config.py
│   ├── models
│   │   └── schemas.py
│   ├── services
│   │   ├── file_filter_service.py
│   │   ├── scan_service.py
│   │   └── zip_service.py
│   ├── static
│   ├── templates
│   │   ├── app.js
│   │   └── styles.css
│   ├── templates
│   │   └── index.html
│   └── main.py
├── tests
│   └── test_filter_and_zip.py
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 파일 필터링 정책
### 포함 확장자
`.js`, `.html`, `.json`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.ejs`, `.hbs`, `.pug`

### 포함 파일
- `package.json`
- `Dockerfile`
- `docker-compose.yml`
- `docker-compose.yaml`
- `config` 관련 파일명
### 포함 파일명
`package.json`, `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`

### config 관련
- 파일명에 `config` 포함 시 포함
- `.env.example`, `.env.sample` 포함
- `.env` 실제 파일 제외

### 제외 경로
`node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`, `__pycache__`, `libs`, `cdn`

### 제외 파일
`*.min.js`, `*.bundle.js`, `*.chunk.js`, `bundle.js`, webpack build output

### 동작 예시
- `jquery-custom-validation.js` → **포함**
- `jquery.min.js` → **제외**

## ZIP 보안 정책
- ZIP Slip 방어
- ZIP 멤버 수 제한
- 압축 해제 총 용량 제한
- ZIP 내부 symlink 차단

## 실행 방법
### 로컬
### 제외 파일 패턴
`*.min.js`, `*.bundle.js`, `*.chunk.js`, `bundle.js`, webpack build output

## ZIP 보안 정책
- ZIP Slip 방어 (relative path 검증)
- ZIP 내부 symlink 엔트리 차단
- ZIP 멤버 수 제한 (`MAX_ZIP_MEMBERS`, 기본 5000)
- 압축 해제 총 크기 제한 (`MAX_UNCOMPRESSED_SIZE_MB`, 기본 200MB)
- 업로드 크기 제한 (`MAX_UPLOAD_SIZE_MB`, 기본 20MB)
- 분석 파일 단위 최대 크기 제한 (`MAX_FILE_SIZE_BYTES`)

## Docker 실행 방법
```bash
cp .env.example .env
docker compose up --build
```
- 접속: http://127.0.0.1:8000
- compose는 localhost 바인딩만 사용
- `/tmp/ai_code_analyzer`는 tmpfs 사용

## 로컬 실행 방법
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## 실행 방법

### 로컬

### 로컬 실행
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
접속: `http://127.0.0.1:8000`

### Docker

### Docker Compose
브라우저에서 `http://localhost:8000` 접속 후 ZIP 업로드.

### Docker Compose 실행
```bash
cp .env.example .env
docker compose up --build
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
> 접근 URL: `http://127.0.0.1:8000`

## .env.example 주요 항목
- `MAX_UPLOAD_SIZE_MB=20`: 업로드 ZIP 최대 크기
- `MAX_ZIP_MEMBERS=5000`: ZIP 내부 엔트리 개수 제한
- `MAX_UNCOMPRESSED_SIZE_MB=200`: 압축 해제 총 크기 제한
- `MAX_FILE_SIZE_BYTES=2097152`: 분석 파일 단위 최대 크기

## 업로드/필터링 정책

### 포함 확장자
`.js`, `.html`, `.json`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.ejs`, `.hbs`, `.pug`

### 주요 파일
- `package.json`
- `Dockerfile`
- config 관련 파일명

### 제외 경로
- `node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`

### 제외 파일 패턴
- `*.min.js`
- `bundle.js`
- webpack build output 파일명 패턴

## 보안 강화 내용
- 업로드 파일명 정규화: `Path(file.filename).name` 사용 및 비정상 파일명 거부
- ZIP Slip 방어
- ZIP symlink entry 차단
- ZIP 멤버 수 제한
- 압축 해제 총 용량 제한
- 바이너리 파일/대용량 단일 파일 분석 제외
- 임시 작업 디렉터리 정리

## API
- `POST /api/upload`
- `GET /api/health`
## 보안 구현 포인트
- 업로드 파일 확장자 `.zip` 제한
- 업로드 용량 제한 20MB
- ZIP Slip 방지 (압축 해제 시 경로 검증)
- 허용 확장자/파일명/설정파일 키워드 기반 포함 정책
- `node_modules`, `vendor`, `dist`, `build` 등 제외
- `jquery`, `bootstrap`, `.min.js`, `bundle.js` 패턴 제외
- 파일 단위 최대 크기 제한(기본 2MB)
- 바이너리 파일 제외
- 업로드/압축 해제 작업 디렉터리 분석 후 정리
- `.env`는 Git 추적 제외 필요

## API
- `POST /api/upload`
  - form-data: `file` (zip)
  - 응답: `path`, `extension`, `size`, `reason` 포함 목록
