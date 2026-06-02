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
  const cards = (playbooks || []).map((pb) => `<div class="card">
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
  return `<section>
    <h2>Promoted Verification Playbooks</h2>
    ${cards || '<div class="card">No promoted verification playbooks</div>'}
  </section>`;
}

function renderCommonConsoleHelper(readable) {
  const helper = readable?.common_console_helper || '';
  if (!helper) return '';
  return `<div class="card">
    <h3>Common Console Helper</h3>
    <p><b>Step 1:</b> paste common_console_helper once.</p>
    <p><b>Step 2:</b> perform the documented page/action.</p>
    <p><b>Step 3:</b> run the short finding-specific console_code.</p>
    <p><b>Step 4:</b> use mutation/replay only after approval.</p>
    ${renderVerificationCode(helper)}
  </div>`;
}

function renderManualPocPlan(plan) {
  const steps = (plan || []).filter((x) => x);
  if (!steps.length) return '';
  return `<div><b>Manual verification plan:</b><ol>${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol></div>`;
}

function renderManualReviewCandidates(candidates) {
  const cards = (candidates || []).map((f) => {
    const ev = (f.evidence || [])[0] || {};
    const poc = f.console_poc || {};
    const verificationNotes = f.verification_notes || [];
    const verificationPlaybook = f.verification_playbook || {};
    const isManualPlan = f.poc_generation_status === 'manual_plan';
    const notRunnableNotes = verificationNotes.filter((n) => n.includes('Not a runnable proof yet'));
    return `<div class="card">
      <h3>${esc(f.title)}</h3>
      <p><b>Manual Review Candidate</b> — <b>Not automatically confirmed vulnerability</b></p>
      <p><b>Type:</b> ${esc(f.vulnerability_type)} / <b>Risk:</b> ${esc(f.severity)} / <b>Confidence:</b> ${esc(f.confidence)}</p>
      ${notRunnableNotes.length ? `<p style="color:#b91c1c;font-weight:700;">⚠ ${notRunnableNotes.map(esc).join(' / ')}</p>` : ''}
      ${isManualPlan && f.poc_generation_reason ? `<p><b>Why no runnable PoC:</b> ${esc(f.poc_generation_reason)}</p>` : ''}
      <p><b>Source location:</b> ${esc(formatLocation(f))}</p>
      <p><b>function_name:</b> ${esc(f.function_name || 'N/A')}</p>
      <p><b>Summary:</b> ${esc(f.summary)}</p>
      <p><b>Affected files:</b> ${(f.affected_files || []).map(esc).join(', ')}</p>
      <p><b>Evidence reason:</b> ${esc(ev.reason || '')}</p>
      <p><b>root_cause:</b> ${esc(f.root_cause || '')}</p>
      <div><b>data_flow:</b> ${renderDataFlow(f.data_flow, ev.data_flow || [])}</div>
      <div><b>breakpoint_plan:</b> ${renderPlan(f.breakpoint_plan)}</div>
      <p><b>Attack scenario:</b> ${(f.attack_scenario || []).map(esc).join(' → ')}</p>
      ${isManualPlan ? renderManualPocPlan(f.manual_poc_plan) : ''}
      ${!isManualPlan && poc.code ? `<p><b>Capture hint (install common_console_helper first):</b></p>${renderVerificationCode(poc.code)}` : ''}
      ${!isManualPlan && poc.steps && poc.steps.length ? `<p><b>Steps:</b> ${(poc.steps || []).map(esc).join(' / ')}</p>` : ''}
      <p><b>Verification notes:</b> <span style="color:#b91c1c;font-weight:700;">${verificationNotes.map(esc).join(' / ')}</span></p>
      <p><b>Impact:</b> ${esc(f.impact)}</p>
      <p><b>Remediation:</b> ${esc(f.remediation)}</p>
    </div>`;
  }).join('');
  return `<section>
    <h2>Manual Review Candidates</h2>
    ${cards || '<div class="card">No manual review candidates</div>'}
  </section>`;
}

function renderFindings(body) {
  const playbooks = body.readable_analysis?.verification_playbooks ?? [];
  const reviewCandidates = body.readable_analysis?.review_candidates ?? [];
  const playbooksHtml = renderVerificationPlaybooks(playbooks);
  const reviewCandidatesHtml = renderManualReviewCandidates(reviewCandidates);
  const commonHelperHtml = renderCommonConsoleHelper(body.readable_analysis);
  findingsBox.innerHTML = `${commonHelperHtml}${playbooksHtml}${reviewCandidatesHtml}`;
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
