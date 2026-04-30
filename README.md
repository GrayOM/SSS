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
│   │   └── routes.py
│   ├── core
│   │   └── config.py
│   ├── models
│   │   └── schemas.py
│   ├── services
│   │   ├── file_filter_service.py
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

### 로컬 실행
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

브라우저에서 `http://localhost:8000` 접속 후 ZIP 업로드.

### Docker Compose 실행
```bash
cp .env.example .env
docker compose up --build
```

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
