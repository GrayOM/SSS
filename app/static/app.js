const form = document.getElementById('analyze-form');
const fileInput = document.getElementById('zip-file');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const findingsBox = document.getElementById('findings');
const downloadBtn = document.getElementById('download-json');
let lastResult = null;

function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

downloadBtn.disabled = true;

function renderSummary(body) {
  const lines = [
    `스캔 파일 수: ${body.upload.total_files_scanned}`,
    `분석 대상 파일 수: ${body.content_load.loaded_count}`,
    `Chunk 수: ${body.chunks.total_chunks}`,
    `일반 finding 수: ${body.analysis.finding_count}`,
    `Readable finding 수: ${body.readable_analysis?.finding_count ?? 0}`,
  ];
  summaryBox.innerHTML = `<div class="card"><h3>요약</h3><ul>${lines.map((x) => `<li>${esc(x)}</li>`).join('')}</ul></div>`;
}

function renderFindings(body) {
  const findings = body.readable_analysis?.findings ?? [];
  findingsBox.innerHTML = findings.map((f) => {
    const ev = (f.evidence || [])[0] || {};
    const poc = f.console_poc || {};
    const hasPocCode = !!poc.code;
    const verificationNotes = f.verification_notes || [];
    return `<div class="card">
      <h3>${esc(f.title)}</h3>
      <p><b>유형:</b> ${esc(f.vulnerability_type)} / <b>위험도:</b> ${esc(f.severity)} / <b>신뢰도:</b> ${esc(f.confidence)}</p>
      <p><b>요약:</b> ${esc(f.summary)}</p>
      <p><b>영향 파일:</b> ${(f.affected_files || []).map(esc).join(', ')}</p>
      <p><b>근거 snippet:</b> ${esc(ev.snippet || '')}</p>
      <p><b>근거 사유:</b> ${esc(ev.reason || '')}</p>
      <p><b>데이터 흐름:</b> ${((ev.data_flow || []).map(esc).join(' → '))}</p>
      <p><b>공격 시나리오:</b> ${(f.attack_scenario || []).map(esc).join(' → ')}</p>
      <p><b>PoC 설명:</b> ${esc(poc.description || '')}</p>
      <p><b>사전조건:</b> ${(poc.preconditions || []).map(esc).join(', ')}</p>
      <p><b>단계:</b> ${(poc.steps || []).map(esc).join(' / ')}</p>
      <pre><code>${esc(hasPocCode ? poc.code : 'Console PoC code는 생성되지 않았습니다.')}</code></pre>
      <p><b>예상결과:</b> ${esc(poc.expected_result || '')}</p>
      <p><b>안전성:</b> ${esc(poc.safety || '')}</p>
      <p><b>검증 노트:</b> <span style="color:#b91c1c;font-weight:700;">${verificationNotes.map(esc).join(' / ')}</span></p>
      <p><b>영향도:</b> ${esc(f.impact)}</p>
      <p><b>개선:</b> ${esc(f.remediation)}</p>
    </div>`;
  }).join('') || '<div class="card">Readable finding 없음</div>';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = fileInput.files[0];
  if (!file) {
    statusBox.textContent = 'ZIP 파일을 선택해주세요';
    return;
  }

  const fd = new FormData();
  fd.append('file', file);
  statusBox.textContent = '분석 중...';
  summaryBox.innerHTML = '';
  findingsBox.innerHTML = '';
  downloadBtn.disabled = true;
  form.querySelector('button[type="submit"]').disabled = true;

  try {
    const res = await fetch('/api/analyze', { method: 'POST', body: fd });
    const body = await res.json();
    if (!res.ok) throw new Error(body.detail || '분석 실패');
    lastResult = body;
    renderSummary(body);
    renderFindings(body);
    statusBox.textContent = '분석 완료';
    downloadBtn.disabled = false;
  } catch (err) {
    statusBox.textContent = `오류: ${err.message}`;
  } finally {
    form.querySelector('button[type="submit"]').disabled = false;
  }
});

downloadBtn.addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'analysis_result.json';
  a.click();
  URL.revokeObjectURL(url);
});
