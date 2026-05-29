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

function listHtml(items, emptyText = 'N/A') {
  const values = (items || []).filter((x) => x !== null && x !== undefined && String(x).trim() !== '');
  if (!values.length) return esc(emptyText);
  return `<ul>${values.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`;
}

function formatLocation(item) {
  const path = item?.source_path || item?.breakpoint_plan?.file || '';
  const start = item?.start_line;
  const end = item?.end_line;
  if (!path) return 'N/A';
  if (Number.isInteger(start) && Number.isInteger(end)) return `${path}:${start}-${end}`;
  if (Number.isInteger(start)) return `${path}:${start}`;
  return path;
}

function renderPlan(plan) {
  if (!plan) return esc('N/A');
  const rows = Object.entries(plan)
    .filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '')
    .map(([key, value]) => `<li><b>${esc(key)}:</b> ${esc(Array.isArray(value) ? value.join(', ') : value)}</li>`);
  return rows.length ? `<ul>${rows.join('')}</ul>` : esc('N/A');
}

function renderDataFlow(flow, evidenceFlow = []) {
  if (flow && typeof flow === 'object' && !Array.isArray(flow)) {
    const rows = ['user_action', 'handler', 'api_call_or_sink', 'missing_guard_or_validation']
      .filter((key) => flow[key])
      .map((key) => `<li><b>${esc(key)}:</b> ${esc(flow[key])}</li>`);
    return rows.length ? `<ul>${rows.join('')}</ul>` : esc('N/A');
  }
  return listHtml(evidenceFlow, 'N/A');
}

function renderVerificationCode(code) {
  return `<pre><code>${esc(code || 'Console verification code was not generated.')}</code></pre>`;
}

function renderVerificationPlaybooks(playbooks) {
  return (playbooks || []).map((pb) => `<div class="card">
    <h3>${esc(pb.title || pb.vulnerability_title || 'Verification Playbook')}</h3>
    <p><b>Source location:</b> ${esc(formatLocation(pb))}</p>
    <p><b>function_name:</b> ${esc(pb.function_name || 'N/A')}</p>
    <p><b>Risk:</b> ${esc(pb.risk_type || '')} / <b>Confidence:</b> ${esc(pb.confidence || '')}</p>
    <p><b>root_cause:</b> ${esc(pb.root_cause || '')}</p>
    <p><b>why_exploitable:</b> ${esc(pb.why_exploitable || '')}</p>
    <div><b>data_flow:</b> ${renderDataFlow(pb.data_flow)}</div>
    <div><b>breakpoint_plan:</b> ${renderPlan(pb.breakpoint_plan)}</div>
    <div><b>poc_injection_plan:</b> ${renderPlan(pb.poc_injection_plan)}</div>
    <p><b>verification_playbook.console_code:</b></p>
    ${renderVerificationCode(pb.console_code)}
    <div><b>success_criteria:</b> ${listHtml(pb.success_criteria)}</div>
    <div><b>failure_criteria:</b> ${listHtml(pb.failure_criteria)}</div>
  </div>`).join('');
}

function renderFindings(body) {
  const findings = body.readable_analysis?.findings ?? [];
  const playbooks = body.readable_analysis?.verification_playbooks ?? [];
  const findingsHtml = findings.map((f) => {
    const ev = (f.evidence || [])[0] || {};
    const poc = f.console_poc || {};
    const verificationNotes = f.verification_notes || [];
    const verificationPlaybook = f.verification_playbook || {};
    return `<div class="card">
      <h3>${esc(f.title)}</h3>
      <p><b>Type:</b> ${esc(f.vulnerability_type)} / <b>Risk:</b> ${esc(f.severity)} / <b>Confidence:</b> ${esc(f.confidence)}</p>
      <p><b>Source location:</b> ${esc(formatLocation(f))}</p>
      <p><b>function_name:</b> ${esc(f.function_name || 'N/A')}</p>
      <p><b>Summary:</b> ${esc(f.summary)}</p>
      <p><b>Affected files:</b> ${(f.affected_files || []).map(esc).join(', ')}</p>
      <p><b>Evidence reason:</b> ${esc(ev.reason || '')}</p>
      <p><b>root_cause:</b> ${esc(f.root_cause || '')}</p>
      <p><b>why_exploitable:</b> ${esc(f.why_exploitable || '')}</p>
      <div><b>data_flow:</b> ${renderDataFlow(f.data_flow, ev.data_flow || [])}</div>
      <div><b>breakpoint_plan:</b> ${renderPlan(f.breakpoint_plan)}</div>
      <div><b>poc_injection_plan:</b> ${renderPlan(f.poc_injection_plan)}</div>
      <p><b>Attack scenario:</b> ${(f.attack_scenario || []).map(esc).join(' → ')}</p>
      <p><b>PoC description:</b> ${esc(poc.description || '')}</p>
      <p><b>Preconditions:</b> ${(poc.preconditions || []).map(esc).join(', ')}</p>
      <p><b>Steps:</b> ${(poc.steps || []).map(esc).join(' / ')}</p>
      ${renderVerificationCode(poc.code)}
      <p><b>verification_playbook.console_code:</b></p>
      ${renderVerificationCode(verificationPlaybook.console_code)}
      <div><b>success_criteria:</b> ${listHtml(f.success_criteria || verificationPlaybook.success_criteria)}</div>
      <div><b>failure_criteria:</b> ${listHtml(f.failure_criteria || verificationPlaybook.failure_criteria)}</div>
      <p><b>Expected result:</b> ${esc(poc.expected_result || '')}</p>
      <p><b>Safety:</b> ${esc(poc.safety || '')}</p>
      <p><b>Verification notes:</b> <span style="color:#b91c1c;font-weight:700;">${verificationNotes.map(esc).join(' / ')}</span></p>
      <p><b>Impact:</b> ${esc(f.impact)}</p>
      <p><b>Remediation:</b> ${esc(f.remediation)}</p>
    </div>`;
  }).join('') || '<div class="card">No readable findings</div>';
  const playbooksHtml = renderVerificationPlaybooks(playbooks);
  findingsBox.innerHTML = `${findingsHtml}${playbooksHtml}`;
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
