/* frontend/static/ip-drawer.js
   IP Threat Analysis Drawer — modular, self-contained.
   Depends on: window.API (set by main.js), showToast (main.js), _qRows (main.js)
   Exposes:    window.openIpDrawer(ip), window.closeIpDrawer()
*/

// ── Build drawer DOM ──────────────────────────────────────────────────────────
(function _initDrawerDOM() {
  // Backdrop overlay
  const overlay = document.createElement('div');
  overlay.id = 'ip-drawer-overlay';
  overlay.onclick = () => closeIpDrawer();
  overlay.style.cssText = [
    'display:none',
    'position:fixed',
    'top:0','left:0','right:0','bottom:0',
    'z-index:9990',
    'background:rgba(0,0,0,0.55)',
    'backdrop-filter:blur(3px)',
    '-webkit-backdrop-filter:blur(3px)',
  ].join(';');
  document.body.appendChild(overlay);

  // Drawer panel — centered modal
  const drawer = document.createElement('div');
  drawer.id = 'ip-drawer';
  drawer.setAttribute('aria-hidden', 'true');
  drawer.style.cssText = [
    'position:fixed',
    'top:50%','left:50%',
    'transform:translate(-50%,-48%) scale(0.97)',
    'width:680px',
    'max-height:85vh',
    'z-index:9991',
    'display:flex',
    'flex-direction:column',
    'overflow:hidden',
    'transition:opacity 0.2s ease, transform 0.2s ease',
    'opacity:0',
    'pointer-events:none',
    'background:var(--card,#111320)',
    'border:1px solid var(--border2,#252840)',
    'border-radius:16px',
    'box-shadow:0 24px 64px rgba(0,0,0,0.7)',
  ].join(';');

  drawer.innerHTML = `
    <!-- Header -->
    <div id="idd-head" style="display:flex;align-items:flex-start;justify-content:space-between;
         padding:22px 22px 16px;border-bottom:1px solid var(--border,#1e2235);flex-shrink:0">
      <div>
        <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#5c6080);
             font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;margin-bottom:5px">
          THREAT ANALYSIS
        </div>
        <div id="idd-ip" style="font-family:var(--mono,'Space Mono',monospace);font-size:22px;
             font-weight:700;color:var(--text,#e8eaf6);letter-spacing:-.3px">—</div>
      </div>
      <button id="idd-close-btn"
        style="background:none;border:1px solid var(--border2,#252840);color:var(--sub2,#8890b0);
               border-radius:8px;width:34px;height:34px;cursor:pointer;font-size:15px;
               display:flex;align-items:center;justify-content:center;flex-shrink:0;
               margin-top:2px;font-family:monospace;line-height:1;padding:0"
        onmouseover="this.style.borderColor='var(--red,#ff3d5a)';this.style.color='var(--red,#ff3d5a)'"
        onmouseout="this.style.borderColor='var(--border2,#252840)';this.style.color='var(--sub2,#8890b0)'"
        onclick="closeIpDrawer()" title="Close (Esc)">✕</button>
    </div>

    <!-- Loading state -->
    <div id="idd-loading" style="display:none;flex:1;align-items:center;justify-content:center;
         gap:12px;color:var(--sub,#5c6080);font-size:13px;
         font-family:var(--mono,'Space Mono',monospace);padding:22px">
      <div id="idd-spinner" style="width:18px;height:18px;border:2px solid var(--border2,#252840);
           border-top-color:var(--blue,#3d6cff);border-radius:50%;
           animation:idd-spin .7s linear infinite;flex-shrink:0"></div>
      <span>Fetching feature data…</span>
    </div>

    <!-- Error state -->
    <div id="idd-error" style="display:none;flex:1;flex-direction:column;align-items:center;
         justify-content:center;padding:32px;gap:14px;text-align:center">
      <div style="font-size:28px;color:var(--red,#ff3d5a);font-family:var(--mono,'Space Mono',monospace);font-weight:700">!</div>
      <div id="idd-error-msg"
           style="font-family:var(--mono,'Space Mono',monospace);font-size:12px;
                  color:var(--red,#ff3d5a);line-height:1.8;white-space:pre-wrap;text-align:left;
                  background:rgba(255,61,90,.07);border:1px solid rgba(255,61,90,.25);
                  border-radius:10px;padding:16px 20px;max-width:360px">
        No data available for this IP.
      </div>
      <div style="font-size:11px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace)">
        Flow data may have expired or IP was released.
      </div>
    </div>

    <!-- Content -->
    <div id="idd-content" style="display:none;flex:1;overflow-y:auto;padding:20px 22px 40px;max-height:calc(85vh - 80px)">

      <!-- Verdict banner -->
      <div id="idd-verdict"
           style="border-radius:10px;padding:12px 16px;margin-bottom:20px;font-size:12px;
                  font-family:var(--mono,'Space Mono',monospace);font-weight:700;
                  display:flex;align-items:center;gap:10px;letter-spacing:.02em"></div>

      <!-- Traffic Features -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#5c6080);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:10px">Traffic Features (Last Window)</div>
      <div id="idd-features" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;
           margin-bottom:20px"></div>

      <!-- ML Evaluation -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#5c6080);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:10px">Machine Learning Evaluation</div>
      <div id="idd-ml" style="display:flex;flex-direction:column;gap:14px;margin-bottom:20px"></div>

      <!-- Mitigation Pipeline -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#5c6080);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:12px">Mitigation Pipeline</div>
      <div id="idd-pipeline" style="display:flex;align-items:flex-start;gap:0;margin-bottom:16px">
      </div>

      <!-- History/state extras -->
      <div id="idd-history"
           style="padding-top:14px;border-top:1px solid var(--border,#1e2235);
                  display:flex;flex-wrap:wrap;gap:8px"></div>
    </div>`;

  document.body.appendChild(drawer);

  // Spinner keyframes
  if (!document.getElementById('idd-style')) {
    const st = document.createElement('style');
    st.id = 'idd-style';
    st.textContent = `
      @keyframes idd-spin { to { transform:rotate(360deg) } }
      #ip-drawer-overlay { cursor: pointer; }
    `;
    document.head.appendChild(st);
  }
})();

// ── State ─────────────────────────────────────────────────────────────────────
let _drawerCurrentIp = null;

// ── Public API ────────────────────────────────────────────────────────────────
function openIpDrawer(ip) {
  if (!ip || ip === '—') return;
  _drawerCurrentIp = ip;

  document.getElementById('idd-ip').textContent = ip;
  _iddShow('loading');

  const overlay = document.getElementById('ip-drawer-overlay');
  const drawer  = document.getElementById('ip-drawer');
  overlay.style.display = 'block';
  drawer.style.pointerEvents = 'all';
  drawer.style.opacity   = '1';
  drawer.style.transform = 'translate(-50%,-50%) scale(1)';
  drawer.setAttribute('aria-hidden', 'false');

  _fetchIpDetail(ip);
}

function closeIpDrawer() {
  const overlay = document.getElementById('ip-drawer-overlay');
  const drawer  = document.getElementById('ip-drawer');
  if (overlay) overlay.style.display = 'none';
  if (drawer) {
    drawer.style.opacity       = '0';
    drawer.style.transform     = 'translate(-50%,-48%) scale(0.97)';
    drawer.style.pointerEvents = 'none';
    drawer.setAttribute('aria-hidden', 'true');
  }
  _drawerCurrentIp = null;
}

// Close on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && _drawerCurrentIp) closeIpDrawer();
});

// Expose globally so delegation in main.js can call them
window.openIpDrawer  = openIpDrawer;
window.closeIpDrawer = closeIpDrawer;

// ── Internal helpers ──────────────────────────────────────────────────────────
function _iddShow(which) {
  // which: 'loading' | 'error' | 'content'
  const map = { loading: 'flex', error: 'flex', content: 'block' };
  ['loading','error','content'].forEach(s => {
    const el = document.getElementById(`idd-${s}`);
    if (el) el.style.display = (s === which) ? map[s] : 'none';
  });
}

async function _fetchIpDetail(ip) {
  try {
    const data = await fetch(window.API + `/api/ip_detail/${encodeURIComponent(ip)}`);
    if (!data.ok) throw data;
    const json = await data.json();
    if (_drawerCurrentIp !== ip) return;
    _renderIpDetail(json);
  } catch (err) {
    if (_drawerCurrentIp !== ip) return;

    // Try to build a fallback from quarantine row data already in the DOM
    const qRow = typeof _qRows !== 'undefined' ? _qRows.get(ip) : null;
    if (qRow) {
      const cells  = qRow.querySelectorAll('td');
      const vector = cells[2] ? cells[2].textContent.trim() : '—';
      const score  = parseFloat(cells[3] ? cells[3].textContent : '0') || 0;
      const conf   = parseFloat(cells[4] ? cells[4].textContent : '0') || 0;
      const fallback = {
        src_ip:   ip,
        features: { pkt_count:0, syn_ratio:0, pps:0, byte_rate:0,
                    active_flows:0, sw_delta:0, inter_arrival:0,
                    unique_ports:0, duration_sec:0 },
        ml:    { if_score:score, is_anomaly:true, attack_class:vector, confidence:conf },
        state: { phase:'—', priority:'—', action_taken:'Quarantined' },
        thresholds: { if_threshold: null, rf_conf_gate: null },
      };
      if (typeof showToast === 'function') showToast(`Showing cached data for ${ip}`);
      _renderIpDetail(fallback);
      return;
    }

    // Show visible error
    const status = err && err.status;
    let msg;
    if (status === 404) {
      msg = `404 — No live data found for\n${ip}\n\nFlow data expired or IP was released.`;
    } else if (status) {
      msg = `HTTP ${status} error\nURL: ${window.API}/api/ip_detail/${ip}`;
    } else {
      msg = `Network error — cannot reach backend.\nURL: ${window.API}/api/ip_detail/${ip}\n\nIs the Flask backend running on port 5000?`;
    }
    document.getElementById('idd-error-msg').textContent = msg;
    _iddShow('error');
    if (typeof showToast === 'function')
      showToast(`Drawer: ${status ? 'HTTP ' + status : 'network error'} for ${ip}`, true);
  }
}

function _renderIpDetail(d) {
  const f  = d.features   || {};
  const ml = d.ml         || {};
  const st = d.state      || {};
  const th = d.thresholds || {};

  // ── Verdict banner ────────────────────────────────────────────
  const isAnomaly = ml.is_anomaly;
  const verdict   = document.getElementById('idd-verdict');
  verdict.style.cssText += isAnomaly
    ? ';background:rgba(255,61,90,.08);border:1px solid rgba(255,61,90,.25);color:var(--red,#ff3d5a)'
    : ';background:rgba(0,214,143,.07);border:1px solid rgba(0,214,143,.22);color:var(--green,#00d68f)';
  verdict.innerHTML = isAnomaly
    ? `<span style="font-size:13px;font-weight:900;letter-spacing:.05em">ANOMALY</span> &mdash; ${ml.attack_class || 'Unknown'}`
    : `<span style="font-size:13px;font-weight:900;letter-spacing:.05em">NORMAL TRAFFIC</span>`;

  // ── Traffic features grid ─────────────────────────────────────
  const feats = [
    ['SYN Packet Ratio',           `${((f.syn_ratio||0)*100).toFixed(1)}%`,  f.syn_ratio||0,    1,     'var(--red,#ff3d5a)'],
    ['Active Flow Count',          (f.active_flows||0).toLocaleString(),     Math.min(f.active_flows||0, 2000), 2000, 'var(--blue,#3d6cff)'],
    ['Flow Rate (pps)',             `${(f.pps||0).toLocaleString()} pkt/s`,   Math.min(f.pps||0, 50000), 50000, 'var(--blue,#3d6cff)'],
    ['Byte Rate',                  _fmtBytes(f.byte_rate||0),                Math.min(f.byte_rate||0, 1e7), 1e7, 'var(--amber,#ffb02e)'],
    ['Unique Dst Ports',           (f.unique_ports||0).toString(),           Math.min(f.unique_ports||0, 1000), 1000, 'var(--amber,#ffb02e)'],
    ['SW Delta',                   (f.sw_delta||0).toFixed(2),               Math.min(f.sw_delta||0, 500), 500, 'var(--sub2,#8890b0)'],
    ['Inter-Arrival (ms)',         ((f.inter_arrival||0)*1000).toFixed(2),   0, 1, 'var(--sub2,#8890b0)'],
    ['Duration (s)',               (f.duration_sec||0).toFixed(1),           0, 1, 'var(--sub2,#8890b0)'],
  ];

  document.getElementById('idd-features').innerHTML = feats.map(([label, val, raw, max, col]) => {
    const pct = max > 0 ? Math.min((raw / max) * 100, 100) : 0;
    return `
      <div style="background:var(--surface,#0d0f18);border:1px solid var(--border,#1e2235);
           border-radius:9px;padding:10px 14px">
        <div style="font-size:10px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace);
             margin-bottom:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${label}</div>
        <div style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
             color:var(--text,#e8eaf6);margin-bottom:6px">${val}</div>
        <div style="height:3px;background:var(--border2,#252840);border-radius:2px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${col};transition:width .4s;border-radius:2px"></div>
        </div>
      </div>`;
  }).join('');

  // ── ML evaluation bars ────────────────────────────────────────
  const ifScore  = ml.if_score   || 0;
  const rfConf   = ml.confidence || 0;
  const ifThrVal = th.if_threshold != null ? th.if_threshold : null;
  const rfGate   = th.rf_conf_gate != null ? th.rf_conf_gate : null;

  const ifPct  = ifThrVal ? Math.min((ifScore / Math.max(ifThrVal * 2, 1)) * 100, 100) : Math.min(ifScore * 100, 100);
  const rfPct  = Math.min(rfConf, 100);
  const ifOver = ifThrVal != null ? ifScore >= ifThrVal : false;
  const rfOver = rfGate   != null ? rfConf  >= rfGate * 100 : false;

  const ifThrLabel = ifThrVal != null ? `Threshold: &gt; ${ifThrVal.toFixed(4)} triggers alert` : 'Threshold: not available';
  const rfThrLabel = rfGate   != null ? `Threshold: &gt; ${(rfGate * 100).toFixed(0)}% confirms attack` : 'Threshold: not available';

  document.getElementById('idd-ml').innerHTML = `
    <div>
      <div style="display:flex;justify-content:space-between;margin-bottom:5px">
        <span style="font-size:12px;color:var(--sub2,#8890b0);font-family:var(--mono,'Space Mono',monospace)">
          Isolation Forest (Anomaly Score)
        </span>
        <span style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
              color:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)'}">${ifScore.toFixed(4)}</span>
      </div>
      <div style="height:6px;background:var(--border2,#252840);border-radius:3px;overflow:hidden;margin-bottom:4px">
        <div style="height:100%;width:${ifPct}%;background:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)'};
             transition:width .5s;border-radius:3px"></div>
      </div>
      <div style="font-size:10px;color:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--sub,#5c6080)'};
           font-family:var(--mono,'Space Mono',monospace)">
        ${ifThrLabel}
      </div>
    </div>
    <div>
      <div style="display:flex;justify-content:space-between;margin-bottom:5px">
        <span style="font-size:12px;color:var(--sub2,#8890b0);font-family:var(--mono,'Space Mono',monospace)">
          Random Forest (Attack Probability)
        </span>
        <span style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
              color:${rfOver ? 'var(--red,#ff3d5a)' : 'var(--amber,#ffb02e)'}">${rfConf.toFixed(1)}%</span>
      </div>
      <div style="height:6px;background:var(--border2,#252840);border-radius:3px;overflow:hidden;margin-bottom:4px">
        <div style="height:100%;width:${rfPct}%;background:${rfOver ? 'var(--red,#ff3d5a)' : 'var(--amber,#ffb02e)'};
             transition:width .5s;border-radius:3px"></div>
      </div>
      <div style="font-size:10px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace)">
        ${rfThrLabel}
      </div>
    </div>`;

  // ── Mitigation pipeline — dynamic from phase_history ─────────────
  const phaseHistory = d.phase_history || [];
  const pipelineEl   = document.getElementById('idd-pipeline');

  // Always start with 2 fixed steps, then append each phase transition
  const _actionColor = a => {
    if (/blackhole|block/i.test(a)) return 'var(--red,#ff3d5a)';
    if (/ban/i.test(a))             return 'var(--amber,#ffb02e)';
    if (/quarantine/i.test(a))      return 'var(--amber,#ffb02e)';
    if (/rate.limit/i.test(a))      return 'var(--blue,#3d6cff)';
    return 'var(--sub2,#8890b0)';
  };

  const baseSteps = [
    { top:'Traffic Ingress',   bot:'SDN Switch',                          color:'var(--blue,#3d6cff)' },
    { top:'Feature Extractor', bot:ml.attack_class || '—',                color:'var(--blue,#3d6cff)' },
    { top:'Decision Engine',   bot:isAnomaly ? 'Anomalous' : 'Normal',    color:isAnomaly ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)' },
  ];

  // Build phase steps from history — each is a distinct escalation event
  const phaseSteps = phaseHistory.length
    ? phaseHistory.map(ph => ({
        top: ph.phase ? `Phase ${ph.phase}` : 'Action',
        bot: ph.action_taken,
        color: _actionColor(ph.action_taken),
        ts:   ph.timestamp ? ph.timestamp.slice(11, 19) : '',
      }))
    : [{ top:'Action Taken', bot: st.action_taken || '—', color: _actionColor(st.action_taken || ''), ts: '' }];

  const allSteps = [...baseSteps, ...phaseSteps];

  pipelineEl.style.cssText = 'display:flex;align-items:flex-start;gap:0;margin-bottom:16px;flex-wrap:wrap;row-gap:12px';
  pipelineEl.innerHTML = allSteps.map((s, i) => `
    <div style="display:flex;align-items:center;flex:1;min-width:80px">
      <div style="display:flex;flex-direction:column;align-items:center;flex:1;min-width:0">
        <div style="width:34px;height:34px;border-radius:50%;border:2px solid ${s.color};
             display:flex;align-items:center;justify-content:center;
             font-family:var(--mono,'Space Mono',monospace);font-size:12px;font-weight:700;
             color:${s.color};flex-shrink:0;margin-bottom:5px">${i + 1}</div>
        <div style="font-size:9px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace);
             margin-bottom:2px;white-space:nowrap">${s.top}</div>
        <div style="font-size:11px;font-weight:700;color:${s.color};font-family:var(--mono,'Space Mono',monospace);
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:88px;text-align:center">${s.bot}</div>
        ${s.ts ? `<div style="font-size:9px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace);margin-top:2px">${s.ts}</div>` : ''}
      </div>
      ${i < allSteps.length - 1 ? `<div style="color:var(--sub,#5c6080);font-size:14px;padding:0 2px;flex-shrink:0;margin-bottom:20px">›</div>` : ''}
    </div>`).join('');

  // ── History / state metadata pills ───────────────────────────
  const hist = document.getElementById('idd-history');
  const pills = [];
  if (st.offence_count) pills.push(['Offences',    st.offence_count,   'var(--red,#ff3d5a)']);
  if (st.ban_level)     pills.push(['Ban Level',   st.ban_level,       'var(--amber,#ffb02e)']);
  if (st.priority)      pills.push(['Priority',    st.priority,        'var(--blue,#3d6cff)']);
  if (st.phase)         pills.push(['Phase',       st.phase,           'var(--sub2,#8890b0)']);
  if (st.first_seen)    pills.push(['First Seen',  _fmtTs(st.first_seen), 'var(--sub,#5c6080)']);

  hist.innerHTML = pills.length ? pills.map(([k,v,c]) => `
    <div style="background:var(--surface,#0d0f18);border:1px solid var(--border,#1e2235);
         border-radius:7px;padding:6px 12px;display:flex;flex-direction:column;gap:2px">
      <div style="font-size:9px;color:var(--sub,#5c6080);font-family:var(--mono,'Space Mono',monospace);
           text-transform:uppercase;letter-spacing:.08em">${k}</div>
      <div style="font-size:12px;font-weight:700;color:${c};font-family:var(--mono,'Space Mono',monospace)">${v}</div>
    </div>`).join('') : '';

  _iddShow('content');
}

// ── Format helpers ────────────────────────────────────────────────────────────
function _fmtBytes(b) {
  if (b >= 1e6) return `${(b/1e6).toFixed(2)} MB/s`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB/s`;
  return `${b.toFixed(0)} B/s`;
}

function _fmtTs(ts) {
  if (!ts) return '—';
  try { return new Date(ts * 1000).toLocaleTimeString(); } catch { return String(ts); }
}