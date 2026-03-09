import queue
import threading
import time
import logging
from backend.config import (
    WORKER_QUEUE_MAXSIZE, WORKER_ITEM_TIMEOUT_S,
    EXTRACTION_TRIGGER_PKTS, EXTRACTION_TRIGGER_S,
    IF_SCORE_THRESHOLD_OVERRIDE, MIN_FLOW_PKTS_FOR_INFERENCE,
)
from backend.models import if_pipeline, rf_pipeline
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.syn_prefilter import syn_filter

log = logging.getLogger(__name__)

# Work items: (src_ip, flow_stats, switch_stats, enqueued_at)
_queue: queue.Queue = queue.Queue(maxsize=WORKER_QUEUE_MAXSIZE)

# Callback registered by decision_engine so worker can push results without
# importing in a cycle: worker → decision_engine → worker
_result_callback = None


def set_result_callback(fn) -> None:
    global _result_callback
    _result_callback = fn


def submit(src_ip: str, flow_stats: dict, switch_stats: dict) -> None:
    """Enqueue a work item. Drops silently if queue is full."""
    try:
        _queue.put_nowait((src_ip, flow_stats, switch_stats, time.monotonic()))
    except queue.Full:
        pass   # drop — high-load protection


def _process_item(src_ip: str, flow_stats: dict,
                  switch_stats: dict, enqueued_at: float) -> None:

    # Drop flows with no real source IP — these are table-miss/ARP/wildcard
    # flows from OVS that should never reach the ML pipeline
    if not src_ip or src_ip in ("0.0.0.0", ""):
        return

    # ── PPS gate — MUST run before cache check ───────────────────────────────
    # Cache must come AFTER this gate. If cache is checked first, a stale
    # anomaly entry (from pingall/warmup) will keep firing anomaly=True for
    # 3s on every poll even after pps drops to 0 — causing 80%+ FPR.
    pkt_count = int(flow_stats.get("packet_count", 0)) if flow_stats else 0
    pps       = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
    if pkt_count == 0:
        return
    is_syn_flagged   = syn_filter.is_flagged(src_ip)
    # switch_delta_pps set by ryu_controller — detects rand-source floods where
    # per-flow pps is low but switch total is huge. Threshold matches controller (500).
    switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0)) if flow_stats else 0.0
    is_flood_switch  = switch_delta_pps >= 500.0
    # Non-flood: require per-flow pps >= 5 to skip baseline. Flood: always process.
    if not is_flood_switch and pps < 5.0 and not is_syn_flagged:
        tracker.invalidate_cache(src_ip)
        return   # quiet switch + low-rate flow = legit baseline

    # Hard per-item timeout: discard and push fallback block rule
    if time.monotonic() - enqueued_at > WORKER_ITEM_TIMEOUT_S:
        log.warning("Worker timeout for %s — pushing fallback block", src_ip)
        if _result_callback:
            _result_callback(src_ip, None, None, None, None, timed_out=True)
        return

    # Check inference cache AFTER pps gate — only for confirmed high-rate flows
    cached = tracker.get_cached(src_ip)
    if cached:
        if _result_callback:
            _result_callback(
                src_ip,
                cached.if_score, cached.is_anomaly,
                cached.attack_class, cached.confidence,
                flow_stats=flow_stats, switch_stats=switch_stats,
                timed_out=False,
            )
        return

    try:
        # SYN pre-filter check already done above (is_syn_flagged)
        pre_flagged = is_syn_flagged

        if_vec               = if_pipeline.extract_if_features(flow_stats)
        if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)

        # Apply optional threshold override from config — lets us raise the
        # sensitivity bar without retraining the model
        # Raise effective threshold: model default 0.620 is too aggressive.
        # Legit Mininet hosts score 0.62-0.71; real floods score 0.85-0.99.
        # 0.72 creates a clean gap. Reads from config if set, else uses 0.72.
        _effective_threshold = IF_SCORE_THRESHOLD_OVERRIDE if IF_SCORE_THRESHOLD_OVERRIDE is not None else 0.72
        is_anomaly = (if_score >= _effective_threshold)

        # Pre-filter overrides: force anomaly flag even if IF score is borderline
        if pre_flagged and if_score >= 0.58:   # still require some anomaly signal
            is_anomaly = True

        attack_class = "Uncertain"
        confidence   = 0.0

        if is_anomaly:
            rf_vec              = rf_pipeline.extract_rf_features(switch_stats)
            attack_class, confidence = rf_pipeline.run_rf_inference(rf_vec)

        log.info("IF score for %s: %.4f  anomaly=%s", src_ip, if_score, is_anomaly)

        # Cache the result so repeated polls of the same IP within TTL
        # reuse this result instead of re-running the full pipeline.
        # Only cache anomalies — normal results should re-evaluate each poll
        # so that recovering IPs are detected quickly.
        if is_anomaly:
            tracker.set_cache(src_ip, if_score, is_anomaly, attack_class, confidence)

        if _result_callback:
            _result_callback(
                src_ip, if_score, is_anomaly,
                attack_class, confidence,
                flow_stats=flow_stats, switch_stats=switch_stats,
                timed_out=False,
            )

    except Exception:
        log.exception("Worker error processing %s", src_ip)


def _worker_loop() -> None:
    while True:
        try:
            item = _queue.get(timeout=1.0)
            _process_item(*item)
            _queue.task_done()
        except queue.Empty:
            tracker.purge_expired_cache()
            syn_filter.purge_stale()


def start() -> None:
    t = threading.Thread(target=_worker_loop, name="pipeline-worker", daemon=True)
    t.start()
    log.info("Pipeline worker started (queue maxsize=%d)", WORKER_QUEUE_MAXSIZE)