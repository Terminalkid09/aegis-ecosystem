requireAuth();
const TOKEN = localStorage.getItem('kraken_token');

async function loadReports() {
  const list = document.getElementById('report-list');
  list.innerHTML = '<div class="text-center py-8 text-slate-500 text-sm">Loading reports...</div>';
  try {
    const res = await fetch('api/v1/reports/', {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    if (res.status === 401) { window.location.href = 'login'; return; }
    const reports = await res.json();
    renderReports(reports);
  } catch (e) {
    list.innerHTML = `<div class="text-center py-8 text-red-400 text-sm">Failed to load reports: ${escapeHtml(e.message)}</div>`;
  }
}

function renderReports(reports) {
  const list = document.getElementById('report-list');
  if (!reports || reports.length === 0) {
    list.innerHTML = '<div class="text-center py-12 text-slate-500"><p class="text-lg mb-2">No reports yet</p><p class="text-sm">Generate your first report using the button above.</p></div>';
    return;
  }
  list.innerHTML = reports.map(r => `
    <div class="card flex items-center justify-between">
        <div class="flex-1">
            <div class="flex items-center gap-2">
                <span class="text-sm font-semibold">${escapeHtml(r.title)}</span>
                <span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-400">${escapeHtml(r.template)}</span>
            </div>
            <div class="flex items-center gap-4 mt-1 text-xs text-slate-400">
                <span>${escapeHtml(r.created_at ? r.created_at.slice(0, 19).replace('T', ' ') : '')}</span>
                <span>${r.event_count || 0} events</span>
                <span>${(r.total_attacks || 0).toLocaleString()} total attacks</span>
                <span>${(r.unique_ips || 0).toLocaleString()} unique IPs</span>
            </div>
        </div>
        <div class="flex items-center gap-1 ml-4">
            <a href="api/v1/reports/${encodeURIComponent(r.id)}/html" target="_blank"
                class="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded text-xs font-medium transition-colors flex items-center gap-1">
                HTML
            </a>
            <a href="api/v1/reports/${encodeURIComponent(r.id)}/pdf" target="_blank"
                class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 rounded text-xs font-medium transition-colors flex items-center gap-1">
                PDF
            </a>
            <button data-delete-report="${escapeHtml(r.id)}"
                class="px-3 py-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded text-xs font-medium transition-colors">
                Delete
            </button>
        </div>
    </div>
  `).join('');
}

async function deleteReport(id) {
  if (!confirm('Delete this report?')) return;
  try {
    const res = await fetch(`api/v1/reports/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    if (res.ok) loadReports();
    else alert('Failed to delete report');
  } catch (e) {
    alert(e.message);
  }
}

document.getElementById('gen-template').addEventListener('change', function () {
  const descs = {
    professional: 'Full professional report with executive summary, findings matrix, recommendations, and detailed event listing.',
    executive: 'High-level executive summary with key metrics, top threats, and strategic recommendations.',
    technical: 'Detailed technical report with full event data, command logs, credential attempts, and malware samples.',
  };
  document.getElementById('template-desc').textContent = descs[this.value] || '';
});

function showGenerateModal() {
  document.getElementById('generate-modal').classList.remove('hidden');
}

function closeGenerateModal() {
  document.getElementById('generate-modal').classList.add('hidden');
  document.getElementById('gen-status').classList.add('hidden');
}

async function generateReport() {
  const status = document.getElementById('gen-status');
  status.classList.remove('hidden');
  status.textContent = 'Generating report...';
  status.className = 'text-xs text-indigo-400';

  const params = new URLSearchParams({
    title: document.getElementById('gen-title').value,
    template: document.getElementById('gen-template').value,
    include_executive_summary: document.getElementById('gen-summary').checked,
    include_findings_matrix: document.getElementById('gen-matrix').checked,
    include_recommendations: document.getElementById('gen-recs').checked,
    limit: document.getElementById('gen-limit').value,
  });
  const days = document.getElementById('gen-days').value;
  if (days) params.append('days_back', days);

  try {
    const res = await fetch(`api/v1/reports/generate?${params.toString()}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    if (res.status === 401) { window.location.href = 'login'; return; }
    const report = await res.json();
    status.textContent = `Report generated successfully! (${report.event_count} events)`;
    status.className = 'text-xs text-emerald-400';
    closeGenerateModal();
    loadReports();
  } catch (e) {
    status.textContent = `Failed: ${e.message}`;
    status.className = 'text-xs text-red-400';
  }
}

document.getElementById('open-generate').addEventListener('click', showGenerateModal);
document.getElementById('generate-report').addEventListener('click', generateReport);
document.getElementById('cancel-generate').addEventListener('click', closeGenerateModal);
document.getElementById('report-list').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-delete-report]');
  if (btn) deleteReport(btn.dataset.deleteReport);
});

loadReports();
