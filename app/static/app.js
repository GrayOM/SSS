const form = document.getElementById('analyze-form');
const fileInput = document.getElementById('zip-file');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const findingsBox = document.getElementById('findings');
const resultBox = document.getElementById('result');
const downloadBtn = document.getElementById('download-json');
let lastResult = null;

function esc(v) { return String(v ?? '').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }

function renderSummary(body) {
  const lines = [
    `스캔 파일 수: ${body.upload.total_files_scanned}`,
    `분석 대상 파일 수: ${body.content_load.loaded_count}`,
    `Chunk 수: ${body.chunks.total_chunks}`,
    `일반 finding 수: ${body.analysis.finding_count}`,
    `Readable finding 수: ${body.readable_analysis?.finding_count ?? 0}`,
  ];
  summaryBox.innerHTML = `<div class="card"><h3>요약</h3><ul>${lines.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>`;
}

function renderFindings(body) {
  const findings = body.readable_analysis?.findings ?? [];
  findingsBox.innerHTML = findings.map(f => {
    const ev = (f.evidence || [])[0] || {};
    return `<div class="card">
      <h3>${esc(f.title)}</h3>
      <p><b>유형:</b> ${esc(f.vulnerability_type)} / <b>위험도:</b> ${esc(f.severity)} / <b>신뢰도:</b> ${esc(f.confidence)}</p>
      <p><b>영향 파일:</b> ${(f.affected_files || []).map(esc).join(', ')}</p>
      <p><b>근거:</b> ${esc(ev.snippet || '')}</p>
      <p><b>Console PoC:</b> ${esc(f.console_poc?.code || 'N/A')}</p>
      <p><b>영향도:</b> ${esc(f.impact)}</p>
      <p><b>개선:</b> ${esc(f.remediation)}</p>
    </div>`;
  }).join('') || '<div class="card">Readable finding 없음</div>';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = fileInput.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  statusBox.textContent = '분석 중...';
  summaryBox.innerHTML = '';
  findingsBox.innerHTML = '';
  try {
    const res = await fetch('/api/analyze', { method: 'POST', body: fd });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || '분석 실패');
    lastResult = body;
    renderSummary(body);
    renderFindings(body);
    resultBox.textContent = JSON.stringify(body, null, 2);
    statusBox.textContent = '분석 완료';
  } catch (err) {
    statusBox.textContent = `오류: ${err.message}`;
  }
});

downloadBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'analysis_result.json'; a.click();
  URL.revokeObjectURL(url);
});
