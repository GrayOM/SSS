# AI 기반 JS/HTML 취약점 분석 준비 도구

## 프로젝트 개요
로컬 실행형 JS/HTML 취약점 분석 준비 도구입니다.
ZIP을 업로드하면 서버가 안전하게 압축 해제 후 분석 가능한 파일만 선별해 JSON으로 반환합니다.

## 처리 흐름
1. ZIP 업로드
2. 보안 검증 후 압축 해제
3. 파일 필터링
4. 분석 대상 목록 반환

## 실행 방법
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## Docker 실행
```bash
docker compose build
docker compose up
```
