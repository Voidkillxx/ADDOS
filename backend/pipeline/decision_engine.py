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

_stats = {
    "total_packets":     0,
    "malicious_dropped": 0,
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


def get_stats() -> dict:
    with _lock:
        s = _stats.copy()
    # L13 fix: removed dead `total = max(s["total_packets"], 1)` variable
    # that was computed but never referenced anywhere in the returned dict.
    samples = max(s["latency_samples"], 1)
    return {
        "total_packets":     s["total_packets"],
        "malicious_dropped": s["malicious_dropped"],
        "normal_packets":    s["normal_packets"],
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


def _push_sse_event(event: dict) -> None:
    now = time.monotonic()
    key = (event.get("src_ip"), event.get("attack_vector"))
    with _sse_lock:
        last = _sse_dedup.get(key, 0)
        if now - last < _SSE_DEDUP_TTL:
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

    is_uncertain    = (attack_class == "Uncertain")
    below_conf_gate = (confidence is None or confidence < loader.rf_conf_gate)

    if is_uncertain and below_conf_gate:
        with _lock:
            _stats["normal_packets"] += 1
            # Not incrementing false_positives — these flows were never blocked,
            # so they are not operational false positives.
        writer.log_traffic_summary(total=1, threats=0, true_neg=0, fp=0)
        log.debug("Skipping %s — Uncertain %.1f%% < gate %.0f%%",
                  src_ip, (confidence or 0)*100, loader.rf_conf_gate*100)
        return

    if confidence is not None and confidence < 0.60:
        with _lock:
            _stats["normal_packets"] += 1
            # Same reasoning — not blocked, not a real operational FP.
        writer.log_traffic_summary(total=1, threats=0, true_neg=0, fp=0)
        log.debug("Skipping %s — low confidence %.1f%% (class=%s)",
                  src_ip, confidence*100, attack_class)
        return

    predicted_class = "DDoS" if attack_class != "Uncertain" else "Anomaly"
    priority        = _assign_priority(if_score, confidence)
    action_taken    = state_machine.on_detection(
        src_ip, if_score, attack_class, confidence
    )

    with _lock:
        _stats["malicious_dropped"] += 1

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_state    = state_machine._states.get(src_ip)
    phase_label = ip_state.phase_label() if ip_state else None

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

    _push_sse_event({
        "timestamp":       ts,
        "src_ip":          src_ip,
        "predicted_class": predicted_class,
        "attack_vector":   attack_class,
        "confidence":      f"{confidence * 100:.1f}%",
        "priority":        priority,
        "action_taken":    action_taken,
    })


def start() -> None:
    worker.set_result_callback(on_result)
    worker.start()
    log.info("Decision engine ready")