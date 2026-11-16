requireAuth();
const TOKEN = localStorage.getItem('kraken_token');
const PAGE_SIZE = 50;
let currentPage = 0;

const SENSOR_COLORS = {
  ssh: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/50 dark:text-indigo-300',
  http: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/50 dark:text-cyan-300',
  ftp: 'bg-amber-100 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300',
  telnet: 'bg-rose-100 text-rose-700 dark:bg-rose-900/50 dark:text-rose-300',
};

function sensorBadge(s) {
  const cls = SENSOR_COLORS[s] || 'bg-slate-100 text-slate-600';
  return `<span class="text-xs font-semibold px-2 py-0.5 rounded-full ${cls}">${escapeHtml(s).toUpperCase()}</span>`;
}

async function loadEvents(reset = false) {
  if (reset) currentPage = 0;
  const sensor = document.getElementById('filter-sensor').value;
  const ip = document.getElementById('filter-ip').value.trim();
  const skip = currentPage * PAGE_SIZE;

  let url = `api/v1/events/?skip=${skip}&limit=${PAGE_SIZE}`;
  if (sensor) url += `&sensor_type=${encodeURIComponent(sensor)}`;
  if (ip) url += `&attacker_ip=${encodeURIComponent(ip)}`;

  const tbody = document.getElementById('events-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="px-5 py-10 text-center text-slate-400">Loading…</td></tr>';

  try {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${TOKEN}` } });
    if (res.status === 401) { window.location.href = 'login'; return; }
    const events = await res.json();

    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="px-5 py-10 text-center text-slate-400">No events found.</td></tr>';
    } else {
      tbody.innerHTML = events.map(e => {
        const ts = e.timestamp_start ? e.timestamp_start.replace('T', ' ').slice(0, 19) : '';
        const sip = escapeHtml(e.attacker_ip || '');
        const ssensor = escapeHtml(e.sensor_type || '');
        const scountry = escapeHtml(e.country || '');
        const scity = escapeHtml(e.city || '');
        const ssid = escapeHtml(e.session_id || '');
        return `
        <tr class="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors">
            <td class="px-5 py-3 text-xs font-mono text-slate-400">${ts}</td>
            <td class="px-5 py-3 font-mono font-semibold text-indigo-500">${sip}</td>
            <td class="px-5 py-3">${sensorBadge(ssensor)}</td>
            <td class="px-5 py-3">${scountry || '—'}</td>
            <td class="px-5 py-3 text-slate-400 text-xs">${scity || '—'}</td>
            <td class="px-5 py-3">${e.is_known_threat
              ? '<span class="text-xs font-semibold text-rose-500">⚠ Known</span>'
              : '<span class="text-xs text-slate-400">—</span>'}</td>
            <td class="px-5 py-3">
                <a href="api/v1/events/${ssid}" target="_blank"
                   class="text-xs text-indigo-400 hover:text-indigo-300 hover:underline">JSON ↗</a>
            </td>
        </tr>`;
      }).join('');
    }

    document.getElementById('page-info').textContent =
      `Page ${currentPage + 1} · ${events.length} events`;
    document.getElementById('btn-prev').disabled = currentPage === 0;
    document.getElementById('btn-next').disabled = events.length < PAGE_SIZE;
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="px-5 py-10 text-center text-rose-400">Failed to load events.</td></tr>';
  }
}

function changePage(dir) {
  currentPage = Math.max(0, currentPage + dir);
  loadEvents();
}

function resetFilters() {
  document.getElementById('filter-sensor').value = '';
  document.getElementById('filter-ip').value = '';
  loadEvents(true);
}

document.getElementById('apply-filters').addEventListener('click', () => loadEvents(true));
document.getElementById('reset-filters').addEventListener('click', resetFilters);
document.getElementById('btn-prev').addEventListener('click', () => changePage(-1));
document.getElementById('btn-next').addEventListener('click', () => changePage(1));

loadEvents();
