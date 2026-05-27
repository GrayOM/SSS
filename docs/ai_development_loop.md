# AI Development Loop

## 사용법

### Windows
```powershell
./scripts/ai_fix_loop.ps1
```

### Linux/mac
```bash
./scripts/ai_fix_loop.sh
```

## 운영 방식

1. 사용자는 테스트를 실행(또는 loop 스크립트 실행)한다.
2. 스크립트가 pytest 로그를 `.ai/test_report/latest_pytest.log`에 저장한다.
3. 실패 시 `collect_test_report.py`가 compact summary를 생성한다.
4. Codex가 AGENTS.md 원칙을 기준으로 자동 수정한다.
5. 재테스트를 반복한다(기본 최대 3회).
6. 사용자는 최종 diff를 확인하고 직접 commit/merge 한다.

## 금지 사항

- 자동 main merge
- 테스트 약화
- 보안 제한 완화
- 샘플별 하드코딩

## 왜 자동 merge를 하지 않는가

보안 분석 도구 특성상 잘못된 자동 수정이 취약점 탐지 정확도/보안 경계를 훼손할 수 있으므로, 사람 검토 후 수동 merge를 강제한다.
