import time
import logging
import threading
import datetime
import collections
from backend.mitigation.state_machine import state_machine
from backend.database import writer
from backend.pipeline import worker
from backend.models import loader

log = logging.getLogger(__name__)

_lock = threading.Lock()

# Known legit host IPs in the K=4 fat-tree topology — 8/8 split.
# Attacker hosts (odd): h1,h3,h5,h7,h9,h11,h13,h15
# Legit hosts (even):   h2,h4,h6,h8,h10,h12,h14,h16
_LEGIT_HOST_IPS: frozenset = frozenset([
    "10.0.0.2",  # h2
    "10.0.1.2",  # h4
    "10.1.0.2",  # h6
    "10.1.1.2",  # h8
    "10.2.0.2",  # h10
    "10.2.1.2",  # h12
    "10.3.0.2",  # h14
    "10.3.1.2",  # h16
])

_stats = {
    "total_packets":     0,
    "malicious_dropped": 0,   # ML events classified as malicious (not physical drops)
    "actual_pkts_dropped": 0, # F3 fix: real physical packets dropped at OVS level
                               # accumulated from "dropped_delta" ZMQ messages sent
                               # by ryu_controller when blocked flow entries are polled.
                               # This is what the UI should show as "Malicious Dropped".
    "normal_packets":    0,
    "false_positives":   0,
    "ml_processed":      0,
    "total_latency_ms":  0.0,
    "latency_samples":   0,
}

_sse_lock   = threading.Lock()
_sse_buffer: collections.deque = collections.deque(maxlen=200)

_sse_dedup: dict = {}
_SSE_DEDUP_TTL = 30.0  # Bug 3 fix: was 5s, too short for sustained attacks

# ── Pending restores — IPs awaiting baseline traffic restart after manual release
_restore_lock     = threading.Lock()
_pending_restores: set[str] = set()

# ── Scan log — rolling buffer of last 200 flow evaluations for /api/debug/flows
_scan_lock   = threading.Lock()
_scan_buffer: collections.deque = collections.deque(maxlen=200)


def push_scan_result(src_ip: str, pps: float, sw_delta: float,
                     if_score: float, threshold: float, is_anomaly: bool,
                     attack_class: str, confidence: float) -> None:
    """Called by worker for every flow that runs through IF inference."""
    import datetime
    entry = {
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(pps, 1),
        "sw_delta":    round(sw_delta, 1),
        "if_score":    round(if_score, 4),
        "threshold":   round(threshold, 4),
        "is_anomaly":  is_anomaly,
        "attack_class": attack_class if is_anomaly else "Normal",
        "confidence":  f"{confidence*100:.1f}%" if is_anomaly else "—",
    }
    with _scan_lock:
        _scan_buffer.appendleft(entry)


def get_scan_log() -> list[dict]:
    with _scan_lock:
        return list(_scan_buffer)

# ── Pipeline debug log — rolling buffer of last 200 inference results
# Each entry: {src_ip, pps, if_score, threshold, is_anomaly,
#              attack_class, confidence, action, ts}
# Exposed via GET /api/debug so operators can see what the ML pipeline is doing.
_debug_lock   = threading.Lock()
_debug_buffer: collections.deque = collections.deque(maxlen=200)


def get_debug_log() -> list[dict]:
    with _debug_lock:
        return list(reversed(_debug_buffer))   # newest first


def _push_debug(entry: dict) -> None:
    with _debug_lock:
        _debug_buffer.append(entry)


def record_dropped_packets(src_ip: str, delta: int) -> None:
    """Called by ZMQ receiver for every 'dropped_delta' message from ryu_controller.

    F3 fix: accumulates REAL physical packet drop counts from OVS blocked flow
    entries (priority 80/90/100). This gives the UI an accurate 'Malicious Dropped'
    counter instead of the misleading per-ML-event count.

    Call this from zmq_receiver.py when msg["type"] == "dropped_delta":
        from backend.pipeline.decision_engine import record_dropped_packets
        record_dropped_packets(msg["src_ip"], msg["delta"])
    """
    with _lock:
        _stats["actual_pkts_dropped"] += delta


def get_stats() -> dict:
    with _lock:
        s = _stats.copy()
    samples = max(s["latency_samples"], 1)

    # Fix A: use _raw_total_pkts from zmq_receiver as total_packets.
    # Previously total_packets only counted flows that reached on_result()
    # (i.e. passed the MIN_PPS=2.0 gate) — baseline pings at 0.33 pps were
    # never counted → UI showed 8 even though hundreds of packets had flowed.
    # _raw_total_pkts accumulates delta_pkts from EVERY flow_stats message,
    # including below-threshold flows, giving the true total packet count.
    try:
        from backend.transport.zmq_receiver import get_raw_counts
        raw_total = max(get_raw_counts()["raw_total"], s["total_packets"])
    except Exception:
        raw_total = s["total_packets"]  # fallback if receiver not started yet

    # F3 fix: use actual_pkts_dropped (real OVS drops) as malicious_dropped.
    real_dropped = s["actual_pkts_dropped"] if s["actual_pkts_dropped"] > 0 else s["malicious_dropped"]

    # Bug 2+3 fix: actual_pkts_dropped accumulates across ZMQ reconnects but
    # raw_total resets to 0 on each reconnect (_reset_flow_state).  Clamp so
    # dropped can never exceed total — prevents negative normal_packets and the
    # "Malicious Dropped > Total Detected" UI anomaly.
    real_dropped = min(real_dropped, raw_total)

    # normal_packets = total observed − confirmed malicious drops
    normal = max(raw_total - real_dropped, 0)

    return {
        "total_packets":     raw_total,
        "malicious_dropped": real_dropped,
        "normal_packets":    normal,
        "active_threats":    len(state_machine.get_active_list()),
        "fp_rate":           round((s["false_positives"] / max(s["ml_processed"], 1)) * 100, 2),
        "avg_latency_ms":    round(s["total_latency_ms"] / samples, 1),
    }


# ── FP rate fix ────────────────────────────────────────────────────────────────

def record_false_positive(src_ip: str) -> None:
    """Called by quarantine.py on every manual release.

    Manual release = operator confirmed a blocked host was legitimate = real FP.

    H4 fix: also buffers fp=1 into traffic_summary so the PDF report's
    FP rate reflects operational ground truth.  The flush guard in writer.py
    was also fixed (it previously skipped total=0 entries, dropping FP rows).

    Also queues src_ip for auto-restoration of baseline traffic (Feature 2).
    """
    with _lock:
        _stats["false_positives"] += 1
    # H4: write to traffic_summary so report.py sees it (flushed within 5s)
    writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
    # Feature 2: queue for baseline restore polling
    with _restore_lock:
        _pending_restores.add(src_ip)
    log.info("FP recorded for %s (manual release). fp_total=%d",
             src_ip, _stats["false_positives"])


def drain_pending_restores() -> list[str]:
    """Drain and return IPs queued for baseline traffic restoration.

    Called by GET /api/pending_restores, polled by topology.py every 5s.
    """
    with _restore_lock:
        ips = list(_pending_restores)
        _pending_restores.clear()
    return ips


def drain_sse_events() -> list[dict]:
    with _sse_lock:
        events = list(_sse_buffer)
        _sse_buffer.clear()
    return events


def _push_sse_event(event: dict, force: bool = False) -> None:
    now = time.monotonic()
    key = event.get("src_ip")
    with _sse_lock:
        last = _sse_dedup.get(key, 0)
        if not force and now - last < _SSE_DEDUP_TTL:
            return
        _sse_dedup[key] = now
        _sse_buffer.append(event)
        expired = [k for k, t in _sse_dedup.items() if now - t > _SSE_DEDUP_TTL * 10]
        for k in expired:
            del _sse_dedup[k]


def _assign_priority(if_score: float, confidence: float) -> str:
    loader.require_loaded()
    if if_score >= loader.if_threshold * 1.2 and confidence >= 0.75:
        return "High"
    return "Low"


def on_result(src_ip: str, if_score, is_anomaly,
              attack_class, confidence, *,
              flow_stats: dict = None, switch_stats: dict = None,
              timed_out: bool) -> None:
    t_start = time.monotonic()

    with _lock:
        _stats["total_packets"] += 1

    if timed_out:
        state_machine.manual_block(src_ip)
        with _lock:
            _stats["malicious_dropped"] += 1
        log.warning("Fallback block: %s (pipeline timeout)", src_ip)
        return

    writer.log_detection_features(
        src_ip=src_ip,
        if_score=if_score or 0.0,
        is_anomaly=bool(is_anomaly),
        attack_class=attack_class or "Normal",
        confidence=confidence or 0.0,
        flow_stats=flow_stats or {},
        switch_stats=switch_stats or {},
    )

    with _lock:
        _stats["ml_processed"] += 1

    # ── Debug log — record every inference result ─────────────────────────────
    _pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))
    _push_debug({
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(_pps, 2),
        "if_score":    round(if_score or 0.0, 4),
        "threshold":   round(loader.if_threshold, 4) if loader._loaded else 0,
        "is_anomaly":  bool(is_anomaly),
        "attack_class": attack_class or "Normal",
        "confidence":  round((confidence or 0.0) * 100, 1),
        "action":      "pending",
    })

    if not is_anomaly:
        with _lock:
            _stats["normal_packets"] += 1
        writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0)
        return

    loader.require_loaded()

    # IF score > threshold confirmed anomaly — quarantine regardless of RF confidence.
    # RF "Uncertain" just means attack TYPE is unknown, not that it's safe.
    # The IF already confirmed it's anomalous — proceed with mitigation.
    # Low-confidence RF result is shown in UI as "Uncertain" attack vector.
    log.debug("Anomaly confirmed: %s  IF=%.4f  RF=%s  conf=%.1f%%",
              src_ip, if_score, attack_class, (confidence or 0)*100)

    # F4 fix: update recent_pps on the state so _evaluate_phase1 can check
    # whether traffic is still active before escalating to a time ban.
    _recent_pps = float((flow_stats or {}).get("packet_count_per_second", 0.0))
    with state_machine._lock:
        _existing_state = state_machine._states.get(src_ip)
        if _existing_state is not None:
            _existing_state.recent_pps = _recent_pps

    # Bug 3a fix: check if legit host BEFORE mitigation so FPR updates immediately
    # in the UI. Previously this check ran after on_detection() and db writes,
    # causing the FP counter to lag behind what was shown in the dashboard.
    is_known_legit = src_ip in _LEGIT_HOST_IPS
    if is_known_legit:
        with _lock:
            _stats["false_positives"] += 1
        writer.log_traffic_summary(total=0, threats=0, true_neg=0, fp=1)
        log.warning("FALSE POSITIVE detected: %s is a known legit host!", src_ip)

    predicted_class = "DDoS" if attack_class != "Uncertain" else "Anomaly"
    priority        = _assign_priority(if_score, confidence)

    # Check if IP was previously banned and is re-offending
    existing = state_machine._states.get(src_ip)
    if existing is None:
        # Check history for prior bans on this IP
        from backend.database.db import query as _q
        prior = _q(
            "SELECT ban_level, offence_count FROM ip_attack_history WHERE src_ip=? ORDER BY id DESC LIMIT 1",
            (src_ip,)
        )
        if prior and prior[0].get("ban_level", 0) is not None:
            prev_ban   = int(prior[0].get("ban_level", 0) or 0)
            prev_off   = int(prior[0].get("offence_count", 0) or 0)
            if prev_ban > 0 or prev_off > 0:
                state_machine.on_reoffence(src_ip, if_score, attack_class, confidence, prev_ban, prev_off)
                action_taken = state_machine._states[src_ip].action_taken if src_ip in state_machine._states else "Quarantined"
            else:
                action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)
        else:
            action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)
    else:
        action_taken = state_machine.on_detection(src_ip, if_score, attack_class, confidence)

    with _lock:
        _stats["malicious_dropped"] += 1

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_state    = state_machine._states.get(src_ip)
    phase_label = ip_state.phase_label() if ip_state else None

    # Always INSERT a new row — never upsert/overwrite.
    # This ensures re-offences and phase escalations each get their own
    # audit log entry so the operator sees the full history per IP.
    writer.log_mitigation_event({
        "timestamp":       ts,
        "src_ip":          src_ip,
        "predicted_class": predicted_class,
        "attack_vector":   attack_class,
        "confidence":      confidence,
        "priority":        priority,
        "action_taken":    action_taken,
        "if_score":        if_score,
        "phase":           phase_label,
        "is_manual":       0,
        "force_insert":    True,   # never overwrite existing rows
    })
    writer.log_traffic_summary(total=1, threats=1, true_neg=0, fp=0)

    elapsed_ms = (time.monotonic() - t_start) * 1000
    with _lock:
        _stats["total_latency_ms"] += elapsed_ms
        _stats["latency_samples"]  += 1

    # Update debug log entry with confirmed action
    _push_debug({
        "ts":          datetime.datetime.now().strftime("%H:%M:%S"),
        "src_ip":      src_ip,
        "pps":         round(_pps, 2),
        "if_score":    round(if_score or 0.0, 4),
        "threshold":   round(loader.if_threshold, 4) if loader._loaded else 0,
        "is_anomaly":  True,
        "attack_class": attack_class,
        "confidence":  round((confidence or 0.0) * 100, 1),
        "action":      action_taken,
    })

    # Force-push SSE on phase upgrades (Quarantine→TimeBan, →Blackhole)
    # so the audit log always reflects the latest phase, bypassing dedup.
    _phase_upgrade = action_taken in ("Time Ban", "Blackhole")
    _push_sse_event({
        "timestamp":       ts,
        "src_ip":          src_ip,
        "predicted_class": predicted_class,
        "attack_vector":   attack_class,
        "confidence":      f"{confidence * 100:.1f}%",
        "priority":        priority,
        "action_taken":    action_taken,
    }, force=_phase_upgrade)


def start() -> None:
    worker.set_result_callback(on_result)
    worker.start()
    log.info("Decision engine ready")