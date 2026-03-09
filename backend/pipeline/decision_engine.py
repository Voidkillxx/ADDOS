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
    "ml_processed":      0,   # flows that ran IF — correct FPR denominator
    "total_latency_ms":  0.0,
    "latency_samples":   0,
}

# SSE event buffer — drained by api/events.py every 500ms
_sse_lock   = threading.Lock()
_sse_buffer: collections.deque = collections.deque(maxlen=200)

# SSE dedup: prevent same IP flooding audit log (20 switches × same flow = 20 entries)
# Key: (src_ip, attack_vector), Value: last push timestamp
_sse_dedup: dict = {}
_SSE_DEDUP_TTL = 5.0   # seconds — one audit entry per IP per 5s


def get_stats() -> dict:
    with _lock:
        s = _stats.copy()
    total   = max(s["total_packets"], 1)
    samples = max(s["latency_samples"], 1)
    return {
        "total_packets":     s["total_packets"],
        "malicious_dropped": s["malicious_dropped"],
        "normal_packets":    s["normal_packets"],
        "active_threats":    len(state_machine.get_active_list()),
        "fp_rate":           round((s["false_positives"] / max(s["ml_processed"], 1)) * 100, 2),
        "avg_latency_ms":    round(s["total_latency_ms"] / samples, 1),
    }


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
            return   # suppress duplicate — same IP+vector within TTL
        _sse_dedup[key] = now
        _sse_buffer.append(event)
        # Prune expired dedup entries to prevent memory leak
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
    """Registered as worker result callback. Runs in worker thread."""
    t_start = time.monotonic()

    with _lock:
        _stats["total_packets"] += 1

    if timed_out:
        state_machine.manual_block(src_ip)
        with _lock:
            _stats["malicious_dropped"] += 1
        log.warning("Fallback block: %s (pipeline timeout)", src_ip)
        return

    # Log all IF + RF features for every inference (anomaly or not)
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
        _stats["ml_processed"] += 1   # count every flow that ran IF

    if not is_anomaly:
        with _lock:
            _stats["normal_packets"] += 1
        writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0)
        return

    loader.require_loaded()

    # ── Confidence gate ────────────────────────────────────────────────────────
    is_uncertain    = (attack_class == "Uncertain")
    below_conf_gate = (confidence is None or confidence < loader.rf_conf_gate)

    if is_uncertain and below_conf_gate:
        with _lock:
            _stats["normal_packets"]  += 1
            _stats["false_positives"] += 1
        writer.log_traffic_summary(total=1, threats=0, true_neg=0, fp=1)
        log.debug("Skipping %s — Uncertain %.1f%% < gate %.0f%%",
                  src_ip, (confidence or 0)*100, loader.rf_conf_gate*100)
        return

    # Extra gate: any class with confidence < 0.60 = noise, not a real attack
    if confidence is not None and confidence < 0.60:
        with _lock:
            _stats["normal_packets"]  += 1
            _stats["false_positives"] += 1
        writer.log_traffic_summary(total=1, threats=0, true_neg=0, fp=1)
        log.debug("Skipping %s — low confidence %.1f%% (class=%s)",
                  src_ip, confidence*100, attack_class)
        return

    # ── Confirmed threat — proceed with mitigation ────────────────────────────
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