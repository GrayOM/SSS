#!/usr/bin/env bash
set -euo pipefail
MAX_ITERS="${1:-3}"
REPORT_DIR=".ai/test_report"
LOG_FILE="$REPORT_DIR/latest_pytest.log"
SUMMARY_MD="$REPORT_DIR/summary.md"
JSON_SUMMARY="$REPORT_DIR/latest_summary.json"
mkdir -p "$REPORT_DIR"

if ! command -v codex >/dev/null 2>&1; then
  echo "[ERROR] codex CLI not found. Please install/login first." >&2
  exit 2
fi

: > "$SUMMARY_MD"
echo "# AI Fix Loop Summary" >> "$SUMMARY_MD"

for ((i=1;i<=MAX_ITERS;i++)); do
  echo "## Iteration $i" | tee -a "$SUMMARY_MD"
  set +e
  python -m pytest tests/ -v 2>&1 | tee "$LOG_FILE"
  RC=${PIPESTATUS[0]}
  set -e

  python scripts/collect_test_report.py --log "$LOG_FILE" --out "$JSON_SUMMARY" | tee -a "$SUMMARY_MD"

  if [[ $RC -eq 0 ]]; then
    echo "PASS on iteration $i" | tee -a "$SUMMARY_MD"
    exit 0
  fi

  PROMPT="Fix failing tests from $LOG_FILE. Follow AGENTS.md strictly: do not weaken tests/security; keep PoC policy hierarchy; keep anonymization; use utf-8 reads on fixtures. Focus on root causes shown in $JSON_SUMMARY. Edit working tree only; no push/merge."
  codex exec "$PROMPT" || {
    echo "[ERROR] codex exec failed (check auth/config)." | tee -a "$SUMMARY_MD"
    exit 3
  }
done

echo "FAIL after $MAX_ITERS iterations" | tee -a "$SUMMARY_MD"
exit 1
