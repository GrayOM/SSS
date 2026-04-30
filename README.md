# AI 기반 JS/HTML 취약점 분석 업로드 전처리 도구 (2차 안정화)

## 현재 범위
- ZIP 업로드
- 안전한 압축 해제
- 분석 대상 파일 필터링
- 결과 JSON 반환
- Docker 기반 로컬 실행

> AI 분석(Claude/OpenAI API) 모듈은 아직 구현하지 않음.

## 폴더 구조
```
.
├── app
│   ├── api
│   │   ├── routes_ui.py
│   │   └── routes_upload.py
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
│   └── main.py
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 파일 필터링 정책
### 포함 확장자
`.js`, `.html`, `.json`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.ejs`, `.hbs`, `.pug`

### 포함 파일명
`package.json`, `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`

### config 관련
- 파일명에 `config` 포함 시 포함
- `.env.example`, `.env.sample` 포함
- `.env` 실제 파일 제외

### 제외 경로
`node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`, `__pycache__`, `libs`, `cdn`

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
