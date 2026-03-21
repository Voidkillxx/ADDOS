/* frontend/static/main.js
   API_URL is injected by the Jinja2 template as window.API_URL
*/
const API     = window.API_URL;
const POLL_MS = window.POLL_MS || 2000;
const MAX_PTS = window.MAX_PTS || 30;
const MAX_LOG = window.MAX_LOG || 100;

// ── State ─────────────────────────────────────────────────────────────────────
let range  = 'Live';
let prev   = { t: 0, m: 0, n: 0 };
let ifThr  = 0;
let logCt  = 0;

// ── Chart ─────────────────────────────────────────────────────────────────────
const chart = new Chart(document.getElementById('chart').getContext('2d'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Incoming',  data: [], borderColor: '#3d6cff', backgroundColor: 'rgba(61,108,255,.07)', borderWidth: 2, pointRadius: 0, fill: true, tension: .4 },
      { label: 'Blocked',   data: [], borderColor: '#ff3d5a', backgroundColor: 'rgba(255,61,90,.05)',  borderWidth: 2, pointRadius: 0, fill: true, tension: .4, borderDash: [5, 3] },
      { label: 'Forwarded', data: [], borderColor: '#00d68f', backgroundColor: 'rgba(0,214,143,.05)',  borderWidth: 2, pointRadius: 0, fill: true, tension: .4 },
    ],
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 180 },
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { labels: { color: '#5c6080', font: { family: 'Space Mono', size: 10 }, boxWidth: 12 } },
      tooltip: {
        backgroundColor: '#111320', borderColor: '#1e2235', borderWidth: 1,
        titleColor: '#8890b0', bodyColor: '#e8eaf6',
        titleFont: { family: 'Space Mono', size: 10 },
        bodyFont:  { family: 'Space Mono', size: 11 },
      },
    },
    scales: {
      x: { ticks: { color: '#5c6080', font: { family: 'Space Mono', size: 9 }, maxRotation: 0 }, grid: { color: '#1e2235' } },
      y: { ticks: { color: '#5c6080', font: { family: 'Space Mono', size: 9 } }, grid: { color: '#1e2235' }, beginAtZero: true },
    },
  },
});

// ── Range tabs ────────────────────────────────────────────────────────────────
document.getElementById('rtabs').addEventListener('click', e => {
  const btn = e.target.closest('.rt');
  if (!btn) return;
  document.querySelectorAll('.rt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  range = btn.dataset.r;
  if (range !== 'Live') fetchHistory(range);
});

// ── API helpers ───────────────────────────────────────────────────────────────
async function apiFetch(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw r;
  return r.json();
}

// ── Stats polling ─────────────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const s = await apiFetch('/api/stats');

    const ct  = s.total_packets     || 0;
    const cm  = s.malicious_dropped || 0;
    const cn  = s.normal_packets    || 0;
    const tot = Math.max(ct, 1);
    const pctDelta = (c, p) => {
      const d = ((c - p) / Math.max(p, 1)) * 100;
      return (d >= 0 ? '+' : '') + d.toFixed(1) + '%';
    };

    set('c-total',   ct.toLocaleString());
    set('c-total-s', pctDelta(ct, prev.t));
    set('c-mal',     cm.toLocaleString());
    set('c-mal-s',   `-${((cm / tot) * 100).toFixed(1)}%`);
    set('c-norm',    cn.toLocaleString());
    set('c-norm-s',  `+${((cn / tot) * 100).toFixed(1)}%`);
    set('c-thr',     (s.active_threats || 0).toString());
    set('p-rt',      `${s.avg_latency_ms || 0} ms`);

    const fpRate = typeof s.fp_rate === 'number' ? s.fp_rate : 0;
    const fpEl   = document.getElementById('p-fp');
    if (fpEl) {
      fpEl.textContent = `${fpRate.toFixed(1)} %`;
      fpEl.style.color = fpRate === 0 ? 'var(--ok, #00d68f)'
                       : fpRate < 1   ? 'var(--warn, #ffb300)'
                       : fpRate < 5   ? 'var(--warn, #ff8c00)'
                       : 'var(--danger, #ff3d5a)';
    }

    if (range === 'Live') {
      const lt = s.live_total     || 0;
      const lm = s.live_malicious || 0;
      const ln = s.live_normal    || 0;

      if (prev.t !== 0) {
        const now = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        pushChartPoint(now, Math.max(lt - prev.t, 0), Math.max(lm - prev.m, 0), Math.max(ln - prev.n, 0));
      }
      prev = { t: lt, m: lm, n: ln };
    }

  } catch (_) {}
}

// ── Model info — fetched ONCE at boot, never polled again ─────────────────────
// M11 fix: model_info never changes at runtime (loaded once at backend startup).
// Polling it every 2s generated 1,800 pointless HTTP requests per hour per tab.
async function fetchModelInfo() {
  try {
    const info = await apiFetch('/api/model_info');
    if (info.if_accuracy != null) set('p-if', `Anomaly detection accuracy: ${info.if_accuracy.toFixed(1)}%`);
    if (info.rf_accuracy != null) set('p-rf', `Classification accuracy: ${info.rf_accuracy.toFixed(1)}%`);
    if (info.if_threshold)        ifThr = info.if_threshold;
  } catch (_) {}
}

// ── Quarantine polling ────────────────────────────────────────────────────────
async function fetchQuarantine() {
  try {
    const data = await apiFetch('/api/quarantine_list');
    set('q-ct', `${data.length} IP${data.length !== 1 ? 's' : ''}`);
    const tb = document.getElementById('q-body');
    if (!data.length) {
      tb.innerHTML = `<tr><td colspan="7" class="q-empty">No IPs currently under active mitigation.</td></tr>`;
      return;
    }
    tb.innerHTML = data.map(e => {
      const sc  = e.if_score || 0;
      const ts  = e.time_in_phase_sec || 0;

      // L15 fix: to_api_dict() in state_machine.py returns confidence already
      // formatted as a string like "68.1%".  The old code had:
      //   typeof e.confidence === 'number' ? `${(e.confidence*100).toFixed(1)}%` : e.confidence
      // The number branch was always false (typeof "68.1%" === 'string'), so
      // the formatted string was silently used as-is anyway — but the branch
      // was dead code and masked the actual type contract.  Fixed: use the
      // string directly since state_machine guarantees the format.
      const conf   = e.confidence || '—';
      const time   = ts < 60 ? `${ts}s` : `${Math.floor(ts / 60)}m ${ts % 60}s`;
      const scCls  = !ifThr ? 'mono'
                   : sc >= ifThr * 1.2 ? 'sc-red'
                   : sc >= ifThr       ? 'sc-amb'
                   : 'sc-grn';

      // Show TTL remaining if present (Feature 1 — auto-block expiry)
      const ttlRemaining = e.ttl_remaining_sec != null
        ? ` <span style="color:var(--sub);font-size:10px;font-family:var(--mono)">[TTL ${Math.floor(e.ttl_remaining_sec / 60)}m]</span>`
        : '';

      return `<tr>
        <td class="ip">${e.src_ip || '—'}</td>
        <td style="color:var(--sub2);font-size:11px">${e.phase || '—'}${ttlRemaining}</td>
        <td>${renderVector(e.attack_vector || '—')}</td>
        <td class="${scCls}">${sc.toFixed(4)}</td>
        <td class="mono">${conf}</td>
        <td style="color:var(--sub2);font-family:var(--mono);font-size:11px">${time}</td>
        <td><div style="display:flex;gap:6px">
          <button class="q-btn q-rel" onclick="quarantineAction('release','${e.src_ip}')">Release</button>
          <button class="q-btn q-blk" onclick="quarantineAction('block','${e.src_ip}')">Block Now</button>
        </div></td>
      </tr>`;
    }).join('');
  } catch (_) {}
}

// ── Graph history ─────────────────────────────────────────────────────────────
async function fetchHistory(r) {
  try {
    const buckets      = await apiFetch(`/api/graph_history?range=${r}`);
    const d            = chart.data;
    d.labels           = buckets.map(b => b.timestamp.slice(11, 16));
    d.datasets[0].data = buckets.map(b => b.incoming  || 0);
    d.datasets[1].data = buckets.map(b => b.blocked   || 0);
    d.datasets[2].data = buckets.map(b => b.forwarded || 0);
    chart.update();
  } catch (_) {}
}

function pushChartPoint(label, di, db, df) {
  const d = chart.data;
  d.labels.push(label);
  d.datasets[0].data.push(di);
  d.datasets[1].data.push(db);
  d.datasets[2].data.push(df);
  if (d.labels.length > MAX_PTS) {
    d.labels.shift();
    d.datasets.forEach(ds => ds.data.shift());
  }
  chart.update('none');
}

// ── SSE live events ───────────────────────────────────────────────────────────
function connectSSE() {
  const es  = new EventSource(`${API}/api/events`);
  es.onmessage = e => { try { addLogRow(JSON.parse(e.data)); } catch (_) {} };
  es.onerror   = () => { es.close(); setTimeout(connectSSE, 3000); };
}

function addLogRow(ev) {
  const tb          = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  if (logCt >= MAX_LOG) {
    const oldest = tb.querySelector('tr');
    if (oldest) oldest.remove();
  } else {
    logCt++;
  }
  set('log-ct', logCt.toString());

  const tr      = document.createElement('tr');
  tr.className  = 'row-in';
  tr.innerHTML  = `
    <td class="mono">${ev.timestamp      || '—'}</td>
    <td class="ip">${ev.src_ip           || '—'}</td>
    <td>${renderClass(ev.predicted_class || '—')}</td>
    <td>${renderVector(ev.attack_vector  || '—')}</td>
    <td class="mono">${ev.confidence     || '—'}</td>
    <td>${renderPriority(ev.priority     || 'Low')}</td>
    <td>${renderAction(ev.action_taken   || '—')}</td>`;
  tb.insertBefore(tr, tb.firstChild);
}

// ── Quarantine actions ────────────────────────────────────────────────────────
async function quarantineAction(action, ip) {
  try {
    await fetch(`${API}/api/quarantine/${action}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ src_ip: ip }),
    });
    showToast(action === 'release' ? `Released ${ip}` : `Blocked ${ip}`);
    fetchQuarantine();
  } catch (_) {
    showToast('Request failed', true);
  }
}

// ── Report modal ──────────────────────────────────────────────────────────────
function openModal() {
  const today = new Date().toISOString().split('T')[0];
  const week  = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
  document.getElementById('r-start').value    = week;
  document.getElementById('r-end').value      = today;
  document.getElementById('m-err').textContent = '';
  document.getElementById('modal').classList.add('open');
}

function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

document.getElementById('modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

async function submitReport() {
  const sd  = document.getElementById('r-start').value;
  const ed  = document.getElementById('r-end').value;
  const err = document.getElementById('m-err');
  if (!sd || !ed)                                          { err.textContent = 'Select both dates.'; return; }
  if (ed < sd)                                             { err.textContent = 'End must be after start.'; return; }
  if (ed > new Date().toISOString().split('T')[0])         { err.textContent = 'End date cannot be in the future.'; return; }
  err.textContent = '';
  closeModal();
  try {
    const r = await fetch(`${API}/api/report`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ start_date: sd, end_date: ed }),
    });
    if (r.status === 404) { const j = await r.json(); showToast(j.error || 'No data.', true); return; }
    if (!r.ok)            { showToast(`Error: ${r.status}`, true); return; }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `ddos_report_${sd}_to_${ed}.pdf`; a.click();
    URL.revokeObjectURL(url);
    showToast('Report downloaded.');
  } catch (e) { showToast(`Failed: ${e.message}`, true); }
}

// ── Tag renderers ─────────────────────────────────────────────────────────────
const mkTag = (cls, txt) => `<span class="tag ${cls}">${txt}</span>`;

function renderClass(v) {
  if (v === 'DDoS')    return mkTag('t-ddos',    v);
  if (v === 'Anomaly') return mkTag('t-anomaly', v);
  return `<span style="color:var(--sub2)">${v}</span>`;
}

function renderVector(v) {
  const map = { 'SYN Flood': 't-syn', 'UDP Flood': 't-udp', 'ICMP Flood': 't-icmp', 'Uncertain': 't-unc' };
  return map[v] ? mkTag(map[v], v) : `<span style="color:var(--sub2)">${v}</span>`;
}

function renderAction(v) {
  const map = { 'Quarantined': 't-q', 'Rate Limited': 't-rl', 'Blocked': 't-blocked' };
  return map[v] ? mkTag(map[v], v) : `<span style="color:var(--sub2)">${v}</span>`;
}

function renderPriority(v) {
  return v === 'High'
    ? '<span class="p-high">HIGH</span>'
    : '<span class="p-low">LOW</span>';
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function showToast(msg, isErr = false) {
  const el      = document.createElement('div');
  el.className  = 'toast';
  if (isErr) el.style.borderColor = 'rgba(255,61,90,.4)';
  el.textContent = msg;
  document.getElementById('toaster').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Theme toggle ──────────────────────────────────────────────────────────────
let isLight = false;

function toggleTheme() {
  isLight = !isLight;
  document.body.classList.toggle('light', isLight);
  document.getElementById('theme-btn').textContent = isLight ? '☾ Dark Mode' : '☀ Light Mode';

  const gridColor   = isLight ? '#d8dce8' : '#1e2235';
  const tickColor   = isLight ? '#6b7280' : '#5c6080';
  const legendColor = isLight ? '#4b5563' : '#5c6080';

  chart.options.scales.x.grid.color         = gridColor;
  chart.options.scales.y.grid.color         = gridColor;
  chart.options.scales.x.ticks.color        = tickColor;
  chart.options.scales.y.ticks.color        = tickColor;
  chart.options.plugins.legend.labels.color = legendColor;
  chart.options.plugins.tooltip.backgroundColor = isLight ? '#ffffff' : '#111320';
  chart.options.plugins.tooltip.titleColor      = isLight ? '#6b7280' : '#8890b0';
  chart.options.plugins.tooltip.bodyColor       = isLight ? '#111827' : '#e8eaf6';
  chart.options.plugins.tooltip.borderColor     = isLight ? '#d8dce8' : '#1e2235';
  chart.update();

  localStorage.setItem('adddos-theme', isLight ? 'light' : 'dark');
}

// Restore saved theme on load
(function () {
  if (localStorage.getItem('adddos-theme') === 'light') toggleTheme();
})();

// ── Boot ──────────────────────────────────────────────────────────────────────
fetchStats();
fetchModelInfo();   // M11 fix: called once here, NOT added to setInterval
fetchQuarantine();
connectSSE();
setInterval(fetchStats,      POLL_MS);
setInterval(fetchQuarantine, POLL_MS);
// fetchModelInfo is intentionally absent from setInterval —
// model config is static for the lifetime of the backend process.