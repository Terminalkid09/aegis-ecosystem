requireAuth();
const TOKEN = localStorage.getItem('kraken_token');
const PALETTE = ['#6366f1', '#22d3ee', '#f59e0b', '#f43f5e', '#10b981', '#a78bfa'];

const map = L.map('map', { zoomControl: true, attributionControl: false }).setView([20, 0], 2);
// No external tile layer: markers remain usable in an air-gapped network.

let timelineChart, countriesChart, sensorsChart;

async function loadStats() {
  try {
    const res = await fetch('api/v1/events/stats', { headers: { Authorization: `Bearer ${TOKEN}` } });
    if (res.status === 401) { window.location.href = 'login'; return; }
    const d = await res.json();

    document.getElementById('stat-total').textContent = d.total_attacks.toLocaleString();
    document.getElementById('stat-today').textContent = d.attacks_today.toLocaleString();
    document.getElementById('stat-ips').textContent = d.unique_ips.toLocaleString();

    d.geo_points.forEach(p => {
      L.circleMarker([p.lat, p.lng], {
        radius: 5, color: '#6366f1', fillColor: '#818cf8', fillOpacity: 0.8, weight: 1,
      }).bindPopup(`<b>${escapeHtml(p.ip)}</b><br/>${escapeHtml(p.country || '')}`).addTo(map);
    });

    if (timelineChart) timelineChart.destroy();
    timelineChart = new Chart(document.getElementById('timelineChart'), {
      type: 'line',
      data: {
        labels: d.attacks_over_time.map(x => x.day),
        datasets: [{
          label: 'Attacks',
          data: d.attacks_over_time.map(x => x.count),
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99,102,241,0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 2,
        }],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { maxTicksLimit: 6, color: '#94a3b8' } },
          y: { ticks: { color: '#94a3b8' } },
        },
      },
    });

    if (countriesChart) countriesChart.destroy();
    countriesChart = new Chart(document.getElementById('countriesChart'), {
      type: 'bar',
      data: {
        labels: d.top_countries.map(c => c.country),
        datasets: [{ data: d.top_countries.map(c => c.count), backgroundColor: '#6366f1', borderRadius: 4 }],
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { color: '#94a3b8' } }, y: { ticks: { color: '#94a3b8' } } },
      },
    });

    if (sensorsChart) sensorsChart.destroy();
    sensorsChart = new Chart(document.getElementById('sensorsChart'), {
      type: 'doughnut',
      data: {
        labels: d.top_sensors.map(s => s.sensor.toUpperCase()),
        datasets: [{ data: d.top_sensors.map(s => s.count), backgroundColor: PALETTE }],
      },
      options: { plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } } },
    });
  } catch (e) {
    console.error('Stats load error:', e);
  }
}

async function loadSandboxes() {
  try {
    const res = await fetch('api/v1/containers/active', { headers: { Authorization: `Bearer ${TOKEN}` } });
    const data = await res.json();
    document.getElementById('stat-sandboxes').textContent = Array.isArray(data) ? data.length : 0;
  } catch {
    document.getElementById('stat-sandboxes').textContent = '0';
  }
}

loadStats();
loadSandboxes();
setInterval(loadSandboxes, 15000);
setInterval(loadStats, 60000);
