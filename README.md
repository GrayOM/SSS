# AI 기반 JS/HTML 취약점 분석 준비 도구

## 프로젝트 개요
이 프로젝트는 **로컬 실행형** ZIP 업로드/전처리 도구입니다.
사용자가 업로드한 소스 ZIP을 안전하게 압축 해제하고, 취약점 분석에 필요한 파일만 선별해 JSON 목록으로 반환합니다.
현재 단계는 AI 분석 모듈 진입 전 단계이며, Claude/OpenAI API 연동은 아직 구현하지 않습니다.

## 처리 흐름
1. ZIP 업로드
2. 보안 검증 후 압축 해제
3. 파일 필터링 정책 적용
4. 분석 대상 목록 반환

## 요구 환경
- Python 3.9 이상
- Docker / Docker Compose (선택)

## 파일 필터링 정책
### 포함 확장자
- `.js`, `.html`, `.json`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.ejs`, `.hbs`, `.pug`

### 포함 파일
- `package.json`
- `Dockerfile`
- `docker-compose.yml`
- `docker-compose.yaml`
- `config` 관련 파일

### 허용 env 예시
- `.env.example`
- `.env.sample`

### 제외 규칙
- 실제 `.env` 파일은 분석 대상에서 제외
- 제외 경로: `node_modules`, `vendor`, `dist`, `build`, `coverage`, `.git`, `__pycache__`, `libs`, `cdn`
- 제외 파일: `*.min.js`, `*.bundle.js`, `*.chunk.js`, `bundle.js`, webpack build output

### 예시
- `jquery-custom-validation.js` → 포함
- `jquery.min.js` → 제외

## ZIP 보안 정책
- ZIP Slip 방어
- ZIP 멤버 수 제한
- 압축 해제 총 용량 제한
- symlink entry 차단
- 업로드 용량 제한

## Docker 보안 정책
- 컨테이너 non-root(`appuser`) 실행
- `127.0.0.1:8000:8000` localhost 바인딩
- `/tmp/ai_code_analyzer` tmpfs 사용
- 운영 기본 compose에서 전체 volume mount 없음

## 실행 방법
### 로컬
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

### Docker
```bash
cp .env.example .env
docker compose build
docker compose up
```

## 테스트 방법
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
