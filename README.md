# AI 기반 JS + HTML 소스코드 취약점 분석 준비 도구 (2차 개선)

## 개요
ZIP 업로드/압축해제/파일 선별 파이프라인을 보안적으로 강화했습니다.
AI 연동은 아직 포함하지 않으며, 이후 `analysis_service.py`를 추가하기 쉬운 구조로 분리했습니다.

## 변경된 폴더 구조

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
│   │   ├── app.js
│   │   └── styles.css
│   ├── templates
│   │   └── index.html
│   └── main.py
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 실행 방법

### 로컬
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

### Docker Compose
```bash
cp .env.example .env
docker compose up --build
```

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
