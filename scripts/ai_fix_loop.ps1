param(
  [int]$MaxIters = 3
)
$ErrorActionPreference = 'Stop'
$reportDir = '.ai/test_report'
$logFile = Join-Path $reportDir 'latest_pytest.log'
$summaryMd = Join-Path $reportDir 'summary.md'
$jsonSummary = Join-Path $reportDir 'latest_summary.json'
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
  Write-Error 'codex CLI not found. Please install/login first.'
  exit 2
}

"# AI Fix Loop Summary" | Set-Content -Path $summaryMd -Encoding UTF8

for ($i=1; $i -le $MaxIters; $i++) {
  "## Iteration $i" | Add-Content -Path $summaryMd -Encoding UTF8
  $pytestOut = python -m pytest tests/ -v 2>&1
  $pytestOut | Tee-Object -FilePath $logFile
  $rc = $LASTEXITCODE

  python scripts/collect_test_report.py --log $logFile --out $jsonSummary | Tee-Object -FilePath $summaryMd -Append

  if ($rc -eq 0) {
    "PASS on iteration $i" | Add-Content -Path $summaryMd -Encoding UTF8
    exit 0
  }

  $prompt = "Fix failing tests from $logFile. Follow AGENTS.md strictly: do not weaken tests/security; keep PoC policy hierarchy; keep anonymization; use utf-8 reads on fixtures. Focus on root causes shown in $jsonSummary. Edit working tree only; no push/merge."
  codex exec $prompt
  if ($LASTEXITCODE -ne 0) {
    Write-Error 'codex exec failed (check auth/config).'
    exit 3
  }
}

"FAIL after $MaxIters iterations" | Add-Content -Path $summaryMd -Encoding UTF8
exit 1
