const form = document.getElementById('analyze-form');
const fileInput = document.getElementById('zip-file');
const statusBox = document.getElementById('status');
const summaryBox = document.getElementById('summary');
const findingsBox = document.getElementById('findings');
const downloadBtn = document.getElementById('download-json');
const selectedFileName = document.getElementById('selected-file-name');
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

fileInput.addEventListener('change', () => {
  selectedFileName.textContent = fileInput.files[0]?.name || '선택된 파일 없음';
});

function renderSummary(body) {
  const metrics = [
    ['스캔 파일', body.upload.total_files_scanned],
    ['분석 대상', body.content_load.loaded_count],
    ['Chunk', body.chunks.total_chunks],
    ['일반 Finding', body.analysis.finding_count],
    ['Readable Finding', body.readable_analysis?.finding_count ?? 0],
  ];
  summaryBox.innerHTML = metrics.map(([label, value]) => `<div class="metric-card">
    <span class="metric-label">${esc(label)}</span>
    <span class="metric-value">${esc(value)}</span>
  </div>`).join('');
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
    <span class="badge">Promoted</span>
    <span class="badge">Risk: ${esc(pb.risk_type || 'N/A')}</span>
    <span class="badge">Confidence: ${esc(pb.confidence || 'N/A')}</span>
    <div class="meta-grid">
      <p><b>Source location:</b> ${esc(formatLocation(pb))}</p>
      <p><b>function_name:</b> ${esc(pb.function_name || 'N/A')}</p>
      <p><b>root_cause:</b> ${esc(pb.root_cause || '')}</p>
      <p><b>why_exploitable:</b> ${esc(pb.why_exploitable || '')}</p>
    </div>
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

function renderCommonConsoleHelper(readable, hasPlaybooks) {
  const helper = readable?.common_console_helper || '';
  if (!hasPlaybooks) {
    return `<div class="card alert-card">
      <h3>No browser-console-runnable PoC was generated</h3>
      <p>Only manual review candidates were found. Use the verification steps below - do not paste the Common Console Helper into your browser for these findings.</p>
      <p><b>Why:</b> No finding had a concrete endpoint, page, and user action confirmed from source code. Each candidate requires manual verification before any PoC can be constructed.</p>
    </div>`;
  }
  if (!helper) return '';
  return `<div class="card helper-card">
    <h3>Common Console Helper - paste once before running any playbook</h3>
    <p><b>Step 1:</b> paste common_console_helper once into the browser Console. After pasting, the console will show <code>undefined</code> - this is normal. Look for the <code>[SSS PoC] common helper installed</code> group log to confirm success.</p>
    <p><b>Step 2:</b> navigate to the documented page and perform the documented page/action.</p>
    <p><b>Step 3:</b> run the short finding-specific console_code from the playbook below.</p>
    <p><b>Step 4:</b> use mutation/replay only after approval, in an approved test environment with test data.</p>
    ${renderVerificationCode(helper)}
  </div>`;
}

function renderManualPocPlan(plan) {
  const steps = (plan || []).filter((x) => x);
  if (!steps.length) return '';
  return `<div><b>Manual verification plan:</b><ol>${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol></div>`;
}

const HOOK_MARKERS = [
  'window.fetch = async function',
  'XMLHttpRequest.prototype.open',
  'axios.interceptors.request.use',
  'SSS_REVIEW_POC_STATE',
  'TARGET_ENDPOINT =',
];

function isSafeReviewCode(code) {
  if (!code) return false;
  return !HOOK_MARKERS.some((m) => code.includes(m));
}

function renderManualReviewCandidates(candidates) {
  const cards = (candidates || []).map((f) => {
    const ev = (f.evidence || [])[0] || {};
    const poc = f.console_poc || {};
    const obsPoc = f.observational_poc || {};
    const verificationNotes = f.verification_notes || [];
    const isManualPlan = f.poc_generation_status === 'manual_plan';
    const isObservational = f.poc_generation_status === 'observational';
    const notRunnableNotes = verificationNotes.filter((n) => n.includes('Not a runnable proof yet'));
    // Only render code that has passed the short-capture-hint policy (no hook installers).
    const safeObsCode = isSafeReviewCode(obsPoc.code) ? obsPoc.code : null;
    const safePocCode = isSafeReviewCode(poc.code) ? poc.code : null;
    return `<div class="card">
      <h3>${esc(f.title)}</h3>
      <span class="badge warning">Manual Review Candidate</span>
      <span class="badge warning">Not automatically confirmed vulnerability</span>
      <span class="badge">Risk: ${esc(f.severity || 'N/A')}</span>
      <span class="badge">Confidence: ${esc(f.confidence || 'N/A')}</span>
      ${isManualPlan ? `<p class="danger-text">No runnable Console PoC - manual verification only</p>` : ''}
      <p><b>Type:</b> ${esc(f.vulnerability_type)}</p>
      ${notRunnableNotes.length ? `<p class="danger-text">${notRunnableNotes.map(esc).join(' / ')}</p>` : ''}
      ${f.poc_generation_reason ? `<p><b>Why no runnable PoC:</b> ${esc(f.poc_generation_reason)}</p>` : ''}
      <div class="meta-grid">
        <p><b>Source location:</b> ${esc(formatLocation(f))}</p>
        <p><b>function_name:</b> ${esc(f.function_name || 'N/A')}</p>
        <p><b>Summary:</b> ${esc(f.summary)}</p>
        <p><b>Affected files:</b> ${(f.affected_files || []).map(esc).join(', ')}</p>
        <p><b>Evidence reason:</b> ${esc(ev.reason || '')}</p>
        <p><b>root_cause:</b> ${esc(f.root_cause || '')}</p>
      </div>
      <div><b>data_flow:</b> ${renderDataFlow(f.data_flow, ev.data_flow || [])}</div>
      <div><b>breakpoint_plan:</b> ${renderPlan(f.breakpoint_plan)}</div>
      <p><b>Attack scenario:</b> ${(f.attack_scenario || []).map(esc).join(' -> ')}</p>
      ${isManualPlan ? renderManualPocPlan(f.manual_poc_plan) : ''}
      ${isObservational && safeObsCode ? `
      <p><b>Runtime request discovery hint</b> - <i>Install common_console_helper first. This is still not a confirmed vulnerability.</i></p>
      ${renderVerificationCode(safeObsCode)}
      ${obsPoc.steps && obsPoc.steps.length ? `<p><b>Steps:</b> ${obsPoc.steps.map(esc).join(' / ')}</p>` : ''}
      ${obsPoc.expected_result ? `<p><b>Expected:</b> ${esc(obsPoc.expected_result)}</p>` : ''}
      ${obsPoc.safety ? `<p><b>Safety:</b> ${esc(obsPoc.safety)}</p>` : ''}
      ` : ''}
      ${!isManualPlan && !isObservational && safePocCode ? `<p><b>Capture hint (install common_console_helper first):</b></p>${renderVerificationCode(safePocCode)}` : ''}
      <p><b>Verification notes:</b> <span class="danger-text">${verificationNotes.map(esc).join(' / ')}</span></p>
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
  const commonHelperHtml = renderCommonConsoleHelper(body.readable_analysis, playbooks.length > 0);
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
