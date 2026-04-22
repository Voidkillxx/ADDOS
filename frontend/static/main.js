/* frontend/static/main.js
   API_URL is injected by the Jinja2 template as window.API_URL
*/
const API     = window.API_URL;
const POLL_MS = window.POLL_MS || 2000;
const MAX_PTS = window.MAX_PTS || 30;
const MAX_LOG = window.MAX_LOG || 100;

// ── State ─────────────────────────────────────────────────────────────────────
let range  = 'Live';
let prev   = { t: 0, m: 0, n: 0 };   // chart delta tracking (live line)
let card   = { t: -1, m: -1, n: -1 }; // card percentage tracking (separate!)
let ifThr  = 0;
let logCt  = 0;
// Bug 3 fix: track log rows by src_ip — update in-place instead of duplicating
const _logRows = new Map(); // src_ip → <tr> element

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

    // Card sub-labels: % of total for mal/norm; rate-of-change for total
    // Use separate `card` tracker so it never conflicts with chart `prev`
    const pctChange = (c, p) => {
      if (p < 0) return '—';   // first poll — no meaningful delta yet
      const d = ((c - p) / Math.max(p, 1)) * 100;
      return (d >= 0 ? '+' : '') + d.toFixed(1) + '%';
    };

    set('c-total',   ct.toLocaleString());
    set('c-total-s', pctChange(ct, card.t));
    set('c-mal',     cm.toLocaleString());
    set('c-mal-s',   `-${((cm / tot) * 100).toFixed(1)}%`);
    set('c-norm',    cn.toLocaleString());
    set('c-norm-s',  `+${((cn / tot) * 100).toFixed(1)}%`);
    set('c-thr',     (s.active_threats || 0).toString());
    set('p-rt',      `${s.avg_latency_ms || 0} ms`);

    // Update card tracker
    card = { t: ct, m: cm, n: cn };

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
// Bug 3 fix: DOM-diff the watchlist — update existing rows in-place instead of
// wiping and re-rendering the whole table every poll. This prevents IP rows
// from flashing/jumping and removes the visual duplicate problem.
const _qRows = new Map(); // src_ip → <tr> element

async function fetchQuarantine() {
  try {
    const data = await apiFetch('/api/quarantine_list');
    set('q-ct', `${data.length} IP${data.length !== 1 ? 's' : ''}`);
    const tb = document.getElementById('q-body');

    if (!data.length) {
      _qRows.clear();
      tb.innerHTML = `<tr><td colspan="7" class="q-empty">No IPs currently under active mitigation.</td></tr>`;
      return;
    }

    const activeIps = new Set(data.map(e => e.src_ip));

    // Remove rows no longer in list
    for (const [ip, tr] of _qRows) {
      if (!activeIps.has(ip)) { tr.remove(); _qRows.delete(ip); }
    }

    // Update or insert rows
    data.forEach(e => {
      const sc  = e.if_score || 0;
      const ts  = e.time_in_phase_sec || 0;
      const conf = e.confidence || '—';
      const time = ts < 60 ? `${ts}s` : `${Math.floor(ts / 60)}m ${ts % 60}s`;
      const scCls = !ifThr ? 'mono'
                  : sc >= ifThr * 1.2 ? 'sc-red'
                  : sc >= ifThr       ? 'sc-amb'
                  : 'sc-grn';
      const ttlRemaining = e.ttl_remaining_sec != null
        ? ` <span style="color:var(--amber,#ffb300);font-size:10px;font-family:var(--mono)">[${Math.floor(e.ttl_remaining_sec/60)}m ${e.ttl_remaining_sec%60}s]</span>`
        : '';

      // Show priority badge
      const priBadge = e.priority === 'High'
        ? `<span class="p-high" style="font-size:11px">HIGH </span>`
        : '';

      const inner = `
        <td class="ip">${e.src_ip || '—'}</td>
        <td style="color:var(--sub2);font-size:12px">${priBadge}${e.phase || '—'}${ttlRemaining}</td>
        <td>${renderVector(e.attack_vector || '—')}</td>
        <td class="${scCls}">${sc.toFixed(4)}</td>
        <td class="mono">${conf}</td>
        <td style="color:var(--sub2);font-family:var(--mono);font-size:11px">${time}</td>
        <td><div style="display:flex;gap:6px">
          <button class="q-btn q-rel" onclick="quarantineAction('release','${e.src_ip}')">Release</button>
          <button class="q-btn q-blk" onclick="quarantineAction('block','${e.src_ip}')">Blackhole</button>
        </div></td>`;

      if (_qRows.has(e.src_ip)) {
        // Update stats in-place — no flicker, no duplicate
        _qRows.get(e.src_ip).innerHTML = inner;
      } else {
        const tr = document.createElement('tr');
        tr.innerHTML = inner;
        _qRows.set(e.src_ip, tr);
        tb.appendChild(tr);
      }
    });

    // Remove empty placeholder if present
    const placeholder = tb.querySelector('[colspan]');
    if (placeholder) placeholder.parentElement.remove();

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
// Track the timestamp of the last event we received so reconnects only fetch
// events we actually missed — no duplicates, no wasted data.
let _lastEventTs = '';

async function fetchRecentEvents() {
  try {
    const url = _lastEventTs
      ? `${API}/api/recent_events?limit=100&since=${encodeURIComponent(_lastEventTs)}`
      : `${API}/api/recent_events?limit=100`;
    const r = await fetch(url);
    if (!r.ok) return;
    const events = await r.json();
    // Events come back oldest-first — insert in order so newest ends up on top
    // Use addReplayRow (not addLogRow) so every DB row gets its own table row
    // regardless of IP — the audit log is a full chronological record.
    events.forEach(ev => addReplayRow(ev));
  } catch (_) {}
}

// addReplayRow — inserts a historical row from /api/recent_events.
// Unlike addLogRow (which deduplicates by IP for live updates),
// this always inserts a new row so the full audit history is visible.
function addReplayRow(ev) {
  const tb = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  const ip        = (ev.src_ip    || '—').trim();
  const timestamp = (ev.timestamp || '—').trim();   // strip stray \n from DB

  const html = `
    <td class="mono">${timestamp}</td>
    <td class="ip">${ip}</td>
    <td>${renderClass(ev.predicted_class || '—')}</td>
    <td>${renderVector(ev.attack_vector  || '—')}</td>
    <td class="mono">${ev.confidence     || '—'}</td>
    <td>${renderPriority(ev.priority     || 'Low')}</td>
    <td>${renderAction(ev.action_taken   || '—')}</td>`;

  if (logCt < MAX_LOG) logCt++;
  set('log-ct', logCt.toString());

  const tr = document.createElement('tr');
  tr.innerHTML = html;
  // Insert at top so newest (last in array) ends up at the top
  tb.insertBefore(tr, tb.firstChild);

  // Also register in _logRows so live SSE updates can find & flash this IP
  _logRows.set(ip, tr);
}

function connectSSE() {
  const es = new EventSource(`${API}/api/events`);
  es.onmessage = e => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.timestamp) _lastEventTs = ev.timestamp;
      addLogRow(ev);
    } catch (_) {}
  };
  es.onerror = () => {
    es.close();
    // On reconnect: fetch any events that arrived while we were disconnected
    setTimeout(() => { fetchRecentEvents(); connectSSE(); }, 3000);
  };
}

function addLogRow(ev, isReplay = false) {
  const tb          = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  const ip   = (ev.src_ip    || '—').trim();
  const ts   = (ev.timestamp || '—').trim();   // strip stray \n from DB
  const html = `
    <td class="mono">${ts}</td>
    <td class="ip">${ip}</td>
    <td>${renderClass(ev.predicted_class || '—')}</td>
    <td>${renderVector(ev.attack_vector  || '—')}</td>
    <td class="mono">${ev.confidence     || '—'}</td>
    <td>${renderPriority(ev.priority     || 'Low')}</td>
    <td>${renderAction(ev.action_taken   || '—')}</td>`;

  if (_logRows.has(ip)) {
    // IP already in log — update in-place
    const tr = _logRows.get(ip);
    tr.innerHTML = html;
    if (!isReplay) {
      // Only flash on live updates, not on replay fills
      tr.style.transition = 'background 0.3s';
      tr.style.background = 'rgba(61,108,255,0.15)';
      setTimeout(() => { tr.style.background = ''; }, 600);
    }
    return;
  }

  // New IP — insert row at top
  if (logCt >= MAX_LOG) {
    const oldest = tb.querySelector('tr:last-child');
    if (oldest) {
      const oldIp = oldest.querySelector('.ip');
      if (oldIp) _logRows.delete(oldIp.textContent.trim());
      oldest.remove();
    }
  } else {
    logCt++;
  }
  set('log-ct', logCt.toString());

  const tr     = document.createElement('tr');
  tr.className = isReplay ? '' : 'row-in';  // no slide-in animation for replay
  tr.innerHTML = html;
  _logRows.set(ip, tr);
  tb.insertBefore(tr, tb.firstChild);

  // Fire browser notification for live events only (not replay fills)
  if (!isReplay) _fireNotif(ev);
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
async function openModal() {
  const today = new Date().toISOString().split('T')[0];
  const week  = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];

  // Pre-fill text inputs
  document.getElementById('r-start').value     = week;
  document.getElementById('r-end').value       = today;
  document.getElementById('m-err').textContent = '';
  document.getElementById('modal').classList.add('open');

  // Load history dates then init calendars with pre-selected values
  await _loadHistoryDates();

  const todayDt = new Date();
  const weekDt  = new Date(Date.now() - 7 * 86400000);
  _calState.start = { year: weekDt.getFullYear(), month: weekDt.getMonth(), selected: week };
  _calState.end   = { year: todayDt.getFullYear(), month: todayDt.getMonth(), selected: today };
  _renderCal('start');
  _renderCal('end');
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
  const map = {
    'Quarantined': 't-q',
    'Rate Limited': 't-rl',
    'Time Ban':    't-ban',
    'Blackhole':   't-blocked',
    'Blocked':     't-blocked',
  };
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

// ── Browser Notifications ────────────────────────────────────────────────────
// Request permission once on load. Fires a notification whenever a new
// anomaly event arrives via SSE (live) or is loaded via fetchRecentEvents.
// Throttled to 1 notification per unique IP per 30 seconds to avoid spam.
const _notifCooldown = new Map(); // src_ip → last notified monotonic ms
const _NOTIF_TTL_MS  = 30_000;

function _requestNotifPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

function _fireNotif(ev) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const ip  = (ev.src_ip || '').trim();
  const now = performance.now();
  if (_notifCooldown.has(ip) && now - _notifCooldown.get(ip) < _NOTIF_TTL_MS) return;
  _notifCooldown.set(ip, now);

  const vec    = ev.attack_vector  || 'Unknown';
  const action = ev.action_taken   || '—';
  const conf   = ev.confidence     || '—';
  const pri    = ev.priority       || 'Low';
  const icon   = pri === 'High' ? '🔴' : '🟡';

  try {
    const n = new Notification(`${icon} A-DDoS: ${vec} Detected`, {
      body: `IP: ${ip}  |  Action: ${action}  |  Confidence: ${conf}`,
      icon: '/static/favicon.ico',
      tag:  `addos-${ip}`,   // replaces previous notif for same IP
      requireInteraction: pri === 'High',
    });
    // Auto-close low-priority after 6s
    if (pri !== 'High') setTimeout(() => n.close(), 6000);
  } catch (_) {}
}

// ── Boot ──────────────────────────────────────────────────────────────────────
_requestNotifPermission();
fetchStats();
fetchModelInfo();      // M11 fix: called once, NOT polled
fetchQuarantine();
fetchRecentEvents();   // Pre-fill audit log from DB on page load / reconnect
connectSSE();
setInterval(fetchStats,      POLL_MS);
setInterval(fetchQuarantine, POLL_MS);
// fetchModelInfo is intentionally absent from setInterval —
// model config is static for the lifetime of the backend process.

// ── Calendar widget ───────────────────────────────────────────────────────────
// Text input (type YYYY-MM-DD) + 📅 button that opens a popup calendar.
// Future dates always disabled. Dates without history data disabled + no dot.
// Dates with data show green dot. Today gets blue border.

let _calDates = new Set();
let _calState = {
  start: { year: 0, month: 0, selected: '' },
  end:   { year: 0, month: 0, selected: '' },
};

async function _loadHistoryDates() {
  try {
    const r = await apiFetch('/api/history_dates');
    _calDates = new Set(r.dates || []);
  } catch (_) { _calDates = new Set(); }
}

function _isoDate(dt) {
  return `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
}

function _renderCal(which) {
  const s      = _calState[which];
  const today  = new Date();
  const todayS = _isoDate(today);
  const grid   = document.getElementById(`cal-${which}-grid`);
  const label  = document.getElementById(`cal-${which}-label`);
  if (!grid || !label) return;

  const monthNames = ['January','February','March','April','May','June',
                      'July','August','September','October','November','December'];
  label.textContent = `${monthNames[s.month]} ${s.year}`;

  const first  = new Date(s.year, s.month, 1).getDay();
  const daysIn = new Date(s.year, s.month + 1, 0).getDate();

  let html = '';
  for (let i = 0; i < first; i++) html += `<div class="cal-day cal-empty"></div>`;

  for (let d = 1; d <= daysIn; d++) {
    const ds      = _isoDate(new Date(s.year, s.month, d));
    const isFut   = ds > todayS;
    const hasData = _calDates.has(ds);
    const isSel   = ds === s.selected;
    const isToday = ds === todayS;
    // Only disable future dates — past/today always selectable
    // History dot shown only on dates with actual attack data
    const disabled = isFut;

    let cls = 'cal-day';
    if (disabled) cls += ' cal-disabled';
    if (hasData)  cls += ' cal-has-data';
    if (isSel)    cls += ' cal-selected';
    if (isToday)  cls += ' cal-today';

    const click = disabled ? '' : `onclick="calSelect('${which}','${ds}')"`;
    html += `<div class="${cls}" ${click}>${d}</div>`;
  }
  grid.innerHTML = html;
}

function calNav(which, dir) {
  const s = _calState[which];
  s.month += dir;
  if (s.month > 11) { s.month = 0;  s.year++; }
  if (s.month < 0)  { s.month = 11; s.year--; }
  _renderCal(which);
  event.stopPropagation();
}

function calSelect(which, ds) {
  _calState[which].selected = ds;
  document.getElementById(`r-${which}`).value = ds;
  _renderCal(which);
  // Close popup after selection
  document.getElementById(`cal-${which}-popup`).classList.remove('open');
}

function toggleCal(which) {
  const popup = document.getElementById(`cal-${which}-popup`);
  const other  = which === 'start' ? 'end' : 'start';
  document.getElementById(`cal-${other}-popup`).classList.remove('open');
  popup.classList.toggle('open');
  if (popup.classList.contains('open')) _renderCal(which);
  event.stopPropagation();
}

// Close popups when clicking outside
document.addEventListener('click', () => {
  document.getElementById('cal-start-popup')?.classList.remove('open');
  document.getElementById('cal-end-popup')?.classList.remove('open');
});

// Allow typing date directly into text input — digits and dashes only
function onDateType(which, val) {
  // Strip anything that isn't a digit or dash
  const cleaned = val.replace(/[^\d-]/g, '');
  const el = document.getElementById(`r-${which}`);
  if (el && cleaned !== val) {
    el.value = cleaned;
    val = cleaned;
  }
  // Only sync calendar once we have a full YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(val)) {
    const dt = new Date(val + 'T00:00:00');
    if (!isNaN(dt)) {
      _calState[which].year     = dt.getFullYear();
      _calState[which].month    = dt.getMonth();
      _calState[which].selected = val;
      _renderCal(which);
    }
  }
}

// _initCals is kept for reference but openModal handles init directly
function _initCals() {
  const today    = new Date();
  const lastWeek = new Date(today);
  lastWeek.setDate(today.getDate() - 7);
  _calState.start = { year: lastWeek.getFullYear(), month: lastWeek.getMonth(), selected: '' };
  _calState.end   = { year: today.getFullYear(),    month: today.getMonth(),    selected: '' };
  _renderCal('start');
  _renderCal('end');
}

// Override openModal — this stub intentionally left blank; real openModal is defined above