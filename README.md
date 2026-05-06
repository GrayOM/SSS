# AI 기반 JS/HTML 취약점 분석 준비 도구

## 프로젝트 개요
로컬 실행형 업로드/전처리 웹 애플리케이션입니다.
ZIP을 업로드하면 서버가 안전하게 압축 해제 후 분석 가능한 파일만 선별해 JSON으로 반환합니다.
현재 단계는 AI 분석 진입 전 준비 단계이며, Claude/OpenAI API 연동은 아직 구현하지 않았습니다.

## 처리 흐름
1. ZIP 업로드
2. 보안 검증 후 압축 해제
3. 파일 필터링 정책 적용
4. 분석 대상 목록 반환 (path / extension / size / reason / reason_code / priority / content_hash)

## 요구 환경
- Python 3.9 이상
- Docker / Docker Compose (선택)

## 폴더 구조
```text
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
├── tests
│   └── test_filter_and_zip.py
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── requirements.txt
```
