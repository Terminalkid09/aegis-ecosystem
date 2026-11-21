const OPS_TOKEN = localStorage.getItem('kraken_token');
let topologies = [];
const analysisReports = new Map();

function opsHeaders(extra = {}) {
  return { Authorization: `Bearer ${OPS_TOKEN}`, 'Content-Type': 'application/json', ...extra };
}

async function opsApi(path, options = {}) {
  const headers = opsHeaders(options.headers);
  if (options.body instanceof FormData) delete headers['Content-Type'];
  const res = await fetch(`api/v1/ops${path}`, { credentials: 'include', ...options, headers });
  if (res.status === 401) { window.location.href = 'login'; throw new Error('unauthorized'); }
  if (!res.ok) {
    let detail = `request failed (${res.status})`;
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

function showError(message) {
  const box = document.getElementById('ops-error');
  box.textContent = message;
  box.classList.toggle('hidden', !message);
}

function showKey(key) {
  document.getElementById('ops-key-value').textContent = key;
  document.getElementById('ops-key').classList.remove('hidden');
}

function fmtDate(value) {
  return value ? new Date(value).toLocaleString() : '—';
}

function selectTab(name) {
  document.querySelectorAll('.ops-tab').forEach((button) => {
    const active = button.dataset.tab === name;
    button.className = `ops-tab px-3 py-1.5 rounded-lg text-sm font-medium ${active ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-700'}`;
  });
  document.querySelectorAll('[data-panel]').forEach((panel) => {
    panel.classList.toggle('hidden', panel.dataset.panel !== name);
  });
}

async function loadCampaigns() {
  const rows = await opsApi('/campaigns');
  document.getElementById('campaigns-body').innerHTML = rows.length ? rows.map((row) => `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5">${escapeHtml(row.name)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.status)}</td>
      <td class="px-4 py-2.5 font-mono text-xs">${escapeHtml(row.fingerprint || '—')}</td>
      <td class="px-4 py-2.5 text-xs text-slate-400">${fmtDate(row.created_at)}</td>
    </tr>`).join('') : '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400">No campaigns yet.</td></tr>';
}

async function loadSensors() {
  const rows = await opsApi('/sensors');
  document.getElementById('sensors-body').innerHTML = rows.length ? rows.map((row) => `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5">${escapeHtml(row.name)}<div class="text-[10px] font-mono text-slate-500">${escapeHtml(row.node_id)}</div></td>
      <td class="px-4 py-2.5">${escapeHtml(row.site)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.status)}</td>
      <td class="px-4 py-2.5 font-mono text-xs">${row.config_version} / ${row.applied_version}</td>
      <td class="px-4 py-2.5 text-xs text-slate-400">${fmtDate(row.last_seen)}</td>
      <td class="px-4 py-2.5 text-right">${row.revoked ? '<span class="text-xs text-rose-400">revoked</span>' : `<button class="revoke-node text-xs text-rose-400" data-node="${escapeHtml(row.node_id)}">Revoke</button>`}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-400">No sensor nodes yet.</td></tr>';
  document.querySelectorAll('.revoke-node').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!confirm('Revoke this sensor node immediately?')) return;
      try {
        await opsApi(`/sensors/${encodeURIComponent(button.dataset.node)}/revoke`, { method: 'POST' });
        await loadSensors();
      } catch (error) { showError(error.message); }
    });
  });
}

async function loadTopologies() {
  topologies = await opsApi('/topologies');
  document.getElementById('topologies-body').innerHTML = topologies.length ? topologies.map((row) => `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5">${escapeHtml(row.name)}</td>
      <td class="px-4 py-2.5 text-slate-400">${escapeHtml(row.description || '—')}</td>
      <td class="px-4 py-2.5">${row.active ? 'yes' : 'no'}</td>
      <td class="px-4 py-2.5 text-xs font-mono text-slate-400">${escapeHtml(JSON.stringify(row.spec || {}))}</td>
    </tr>`).join('') : '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400">No topologies yet.</td></tr>';
  const select = document.querySelector('#lab-form select[name="topology_id"]');
  select.innerHTML = '<option value="">No topology</option>' + topologies.map((row) =>
    `<option value="${row.id}">${escapeHtml(row.name)}</option>`).join('');
}

async function loadLabRuns() {
  const rows = await opsApi('/lab-runs');
  document.getElementById('lab-body').innerHTML = rows.length ? rows.map((row) => `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5 font-mono text-xs">${escapeHtml(row.run_id)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.scenario_id)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.mode)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.status)}</td>
      <td class="px-4 py-2.5 text-xs text-slate-400">${fmtDate(row.started_at)}</td>
    </tr>`).join('') : '<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400">No Lab runs yet.</td></tr>';
}

function analysisSummary(report) {
  const iocs = report.iocs || {};
  const detonation = report.detonation || {};
  const behaviour = detonation.status === 'completed'
    ? `${(report.process_tree || []).length} proc · ${(report.dns_history || []).length} DNS`
    : `detonation: ${detonation.status || 'not run'}`;
  return `${(iocs.ips || []).length} IP · ${(iocs.domains || []).length} domain · ` +
    `${(report.zip_entries || []).length} ZIP · ${behaviour}`;
}

function openAnalysisReport(jobId) {
  const report = analysisReports.get(jobId);
  if (!report) return;
  const dialog = document.getElementById('analysis-report-dialog');
  document.getElementById('analysis-report-title').textContent = `Report ${jobId}`;
  document.getElementById('analysis-report-body').textContent = JSON.stringify(report, null, 2);
  if (!dialog.open) dialog.showModal();
}

async function loadAnalysisJobs() {
  const rows = await opsApi('/analysis-jobs');
  analysisReports.clear();
  document.getElementById('analysis-body').innerHTML = rows.length ? rows.map((row) => {
    const report = row.report || {};
    analysisReports.set(row.job_id, report);
    const summary = report.deleted ? 'sample deleted (verified)' : (report.error || row.error || '—');
    const result = Object.keys(report).length && !report.deleted
      ? analysisSummary(report)
      : summary;
    const actions = row.status === 'deleted' ? '' : `
      ${Object.keys(report).length ? `<button class="view-analysis text-xs text-indigo-400 mr-3" data-job="${escapeHtml(row.job_id)}">Report</button>` : ''}
      <button class="delete-analysis text-xs text-rose-400" data-job="${escapeHtml(row.job_id)}">Delete</button>`;
    return `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5">${escapeHtml(row.filename)}</td>
      <td class="px-4 py-2.5 font-mono text-[10px]">${escapeHtml(row.sha256)}</td>
      <td class="px-4 py-2.5">${escapeHtml(row.status)}</td>
      <td class="px-4 py-2.5 text-xs text-slate-400">${escapeHtml(result)}<div class="text-[10px] text-slate-500">${escapeHtml(report.provenance || '')}</div></td>
      <td class="px-4 py-2.5 text-right whitespace-nowrap">${actions}</td>
    </tr>`;
  }).join('') : '<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400">No analysis jobs yet.</td></tr>';
  document.querySelectorAll('.view-analysis').forEach((button) => {
    button.addEventListener('click', () => openAnalysisReport(button.dataset.job));
  });
  document.querySelectorAll('.delete-analysis').forEach((button) => {
    button.addEventListener('click', async () => {
      if (!confirm('Delete this sample and its stored object?')) return;
      try {
        await opsApi(`/analysis-jobs/${encodeURIComponent(button.dataset.job)}`, { method: 'DELETE' });
        await loadAnalysisJobs();
      } catch (error) { showError(error.message); }
    });
  });
}

async function loadSamples() {
  const sha = document.getElementById('sample-sha').value.trim();
  const sensor = document.getElementById('sample-sensor').value;
  const params = new URLSearchParams({ limit: '200' });
  if (sha) params.set('sha256', sha);
  if (sensor) params.set('sensor_type', sensor);
  const rows = await opsApi(`/samples?${params.toString()}`);
  document.getElementById('samples-body').innerHTML = rows.length ? rows.map((row) => `
    <tr class="border-t border-slate-100 dark:border-slate-700/50">
      <td class="px-4 py-2.5">${escapeHtml(row.filename)}</td>
      <td class="px-4 py-2.5 font-mono text-[10px]">${escapeHtml(row.sha256)}</td>
      <td class="px-4 py-2.5">${Number(row.size || 0).toLocaleString()} B</td>
      <td class="px-4 py-2.5">${escapeHtml(row.sensor_type || '—')}</td>
      <td class="px-4 py-2.5 text-xs text-slate-400">${fmtDate(row.timestamp)}</td>
    </tr>`).join('') : '<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400">No samples match the filter.</td></tr>';
}

async function loadAll() {
  showError('');
  try {
    await Promise.all([loadCampaigns(), loadSensors(), loadTopologies(), loadLabRuns(), loadSamples(), loadAnalysisJobs()]);
  } catch (error) {
    showError(error.message);
  }
}

document.getElementById('ops-tabs').addEventListener('click', (event) => {
  const button = event.target.closest('[data-tab]');
  if (button) selectTab(button.dataset.tab);
});
document.getElementById('ops-refresh').addEventListener('click', loadAll);
document.getElementById('sample-filter').addEventListener('click', loadSamples);

document.getElementById('analysis-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await opsApi('/analysis-jobs', { method: 'POST', body: form });
    event.currentTarget.reset();
    await loadAnalysisJobs();
  } catch (error) { showError(error.message); }
});

document.getElementById('campaign-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await opsApi('/campaigns', { method: 'POST', body: JSON.stringify({
      name: form.get('name'), description: form.get('description') || '',
    }) });
    event.currentTarget.reset();
    await loadCampaigns();
  } catch (error) { showError(error.message); }
});

document.getElementById('sensor-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const created = await opsApi('/sensors', { method: 'POST', body: JSON.stringify({
      name: form.get('name'),
      site: form.get('site') || 'default',
      config: { smb_port: Number(form.get('smb_port') || 445), rdp_port: 3389 },
    }) });
    showKey(created.sensor_key);
    event.currentTarget.reset();
    await loadSensors();
  } catch (error) { showError(error.message); }
});

document.getElementById('topology-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await opsApi('/topologies', { method: 'POST', body: JSON.stringify({
      name: form.get('name'), description: form.get('description') || '', spec: {},
    }) });
    event.currentTarget.reset();
    await loadTopologies();
  } catch (error) { showError(error.message); }
});

document.getElementById('lab-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await opsApi('/lab-runs', { method: 'POST', body: JSON.stringify({
      scenario_id: form.get('scenario_id'),
      topology_id: form.get('topology_id') ? Number(form.get('topology_id')) : null,
      mode: 'shadow',
    }) });
    event.currentTarget.reset();
    await loadLabRuns();
  } catch (error) { showError(error.message); }
});

loadAll();
