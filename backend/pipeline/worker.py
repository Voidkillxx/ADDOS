import queue
import threading
import time
import logging
from backend.config import (
    WORKER_QUEUE_MAXSIZE, WORKER_ITEM_TIMEOUT_S,
    EXTRACTION_TRIGGER_PKTS, EXTRACTION_TRIGGER_S,
    IF_SCORE_THRESHOLD_OVERRIDE, MIN_FLOW_PKTS_FOR_INFERENCE,
)
from backend.models import if_pipeline, rf_pipeline, loader, loader
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.syn_prefilter import syn_filter

log = logging.getLogger(__name__)

_queue: queue.Queue = queue.Queue(maxsize=WORKER_QUEUE_MAXSIZE)
_result_callback = None


def set_result_callback(fn) -> None:
    global _result_callback
    _result_callback = fn


def submit(src_ip: str, flow_stats: dict, switch_stats: dict) -> None:
    try:
        _queue.put_nowait((src_ip, flow_stats, switch_stats, time.monotonic()))
    except queue.Full:
        pass


def _process_item(src_ip: str, flow_stats: dict,
                  switch_stats: dict, enqueued_at: float) -> None:

    if not src_ip or src_ip in ("0.0.0.0", ""):
        return

    pkt_count = int(flow_stats.get("packet_count", 0)) if flow_stats else 0
    pps       = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
    if pkt_count == 0:
        return

    is_syn_flagged   = syn_filter.is_flagged(src_ip)
    switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0)) if flow_stats else 0.0
    # Must match ryu_controller threshold (lowered to 20 for faster VM detection)
    is_flood_switch  = switch_delta_pps >= 20.0

    # ── Baseline sensitivity fix (B2 + C1) ────────────────────────────────────
    # EXTRACTION_TRIGGER_S (2.0s) and EXTRACTION_TRIGGER_PKTS (10) were imported
    # but never used — the guard below was dead code.
    #
    # Bug: during flood mode (is_flood_switch=True) the pps<5.0 gate below is
    # bypassed. A legit host with a new OVS flow entry (duration_nsec≈100ms,
    # pkt_count=2) computes pps = 2/0.1 = 20 — 10× its real rate — and is fed
    # to IF with an out-of-distribution value that can push the score over 0.72.
    #
    # Fix: require minimum flow age AND packet count before allowing IF inference.
    # Exemptions (C1 fix): SYN-flagged hosts (need fast action on short flows)
    #                       AND flood-mode rand-source IPs (appear once with 1 pkt,
    #                       no age — removing the flood exemption would blind the
    #                       rand-source detection path entirely).
    #
    # Accepted gap (M7): baseline hosts with young flows CAN still reach IF
    # during flood mode IF switch_delta_pps >= 500.  The IF threshold of 0.72
    # was deliberately set above the 0.62-0.71 band for legit Mininet traffic,
    # providing a safety margin.  Hosts that have been running long enough
    # (>= EXTRACTION_TRIGGER_S OR >= EXTRACTION_TRIGGER_PKTS) are always safe.
    flow_dur = float(flow_stats.get("flow_duration_sec", 0)) if flow_stats else 0.0
    if not is_syn_flagged and not is_flood_switch:
        # Non-flood, non-SYN: enforce minimum age + count guard to prevent
        # inflated pps from sub-second-old flows causing false positives.
        if flow_dur < EXTRACTION_TRIGGER_S and pkt_count < EXTRACTION_TRIGGER_PKTS:
            tracker.invalidate_cache(src_ip)
            return

    # Non-flood low-rate gate — report as normal traffic so UI counters
    # (Normal Traffic, Forwarded) increment during baseline-only periods.
    # No ML inference runs — IF/RF are skipped entirely, zero FP risk.
    if not is_flood_switch and pps < 1.0 and not is_syn_flagged:
        if _result_callback:
            _result_callback(src_ip, 0.0, False, "Normal", 0.0,
                             flow_stats=flow_stats, switch_stats=switch_stats,
                             timed_out=False)
        return

    if time.monotonic() - enqueued_at > WORKER_ITEM_TIMEOUT_S:
        log.warning("Worker timeout for %s — pushing fallback block", src_ip)
        if _result_callback:
            _result_callback(src_ip, None, None, None, None, timed_out=True)
        return

    cached = tracker.get_cached(src_ip)
    _prior_class = None
    _prior_conf  = 0.0
    if cached:
        # F6 fix: lock threshold lowered from 75% to 70% per user requirement.
        # Attack vector locking logic:
        #   - confidence >= 0.70 AND attack_class is a real type (not Uncertain)
        #     → LOCKED forever — never re-run RF, prevents label flipping in
        #       mixed campaigns where switch aggregate stats are polluted by
        #       multiple attack types on the same switch.
        #   - already in Phase 2/3 (Time Ban/Blackhole) → also locked regardless
        #     of confidence — re-running RF mid-ban only risks flipping the label.
        #   - confidence < 0.70 OR class is Uncertain → fall through to re-classify
        #     so Uncertain results get a chance to resolve to a real type.
        from backend.mitigation.state_machine import state_machine
        ip_state     = state_machine._states.get(src_ip)
        already_banned = ip_state is not None and ip_state.phase >= 2

        # Lock if: confidently classified (>=70%, real class) OR already in ban phase
        is_locked = (
            already_banned or
            (cached.confidence >= 0.70 and cached.attack_class != "Uncertain")
        )

        if is_locked:
            if _result_callback:
                _result_callback(
                    src_ip,
                    cached.if_score, cached.is_anomaly,
                    cached.attack_class, cached.confidence,
                    flow_stats=flow_stats, switch_stats=switch_stats,
                    timed_out=False,
                )
            return

        # Confidence < 70% or still Uncertain — fall through to re-classify
        # but preserve the cached class so a re-run returning Uncertain
        # never overwrites a previously confident real classification.
        tracker.invalidate_cache(src_ip)
        # Stash the last known good class so RF re-run can restore it if needed
        _prior_class = cached.attack_class
        _prior_conf  = cached.confidence

    try:
        pre_flagged = is_syn_flagged

        if_vec               = if_pipeline.extract_if_features(flow_stats)
        if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)

        _effective_threshold = (IF_SCORE_THRESHOLD_OVERRIDE
                                if IF_SCORE_THRESHOLD_OVERRIDE is not None
                                else loader.if_threshold)  # Bug1 fix: use contract threshold not hardcoded 0.72
        is_anomaly = (if_score >= _effective_threshold)

        if pre_flagged and if_score >= 0.58:
            is_anomaly = True

        # ── Rand-source flood bypass ───────────────────────────────────────────
        # Only bypass IF when BOTH conditions are met:
        #   1. switch_delta_pps >= 1000 (undeniable flood — well above VM baseline)
        #   2. if_score >= 0.50 (above noise floor — not a clearly normal flow)
        #
        # Rationale: without condition 2, a legitimately normal flow (IF score 0.44)
        # on a switch that happens to be under flood gets force-quarantined even
        # though IF correctly identified it as normal. The score floor ensures we
        # only override IF when the score is at least ambiguous, not clearly benign.
        #
        # Threshold raised 500 → 1000: fixed-IP attacks accumulate packets in one
        # flow so IF detects them normally. The bypass is now only a last-resort
        # safety net for extreme floods where IF is structurally blind.
        # Flood bypass: only force anomaly if score is ABOVE threshold.
        # Old floor was 0.50 — this quarantined below-threshold IPs during floods.
        # Now uses _effective_threshold so it respects the contract value (0.6004).
        if not is_anomaly and switch_delta_pps >= 1000.0 and if_score >= _effective_threshold:
            is_anomaly = True
            log.debug("Flood bypass: %s  sw_delta=%.1f  IF=%.4f → forcing anomaly",
                      src_ip, switch_delta_pps, if_score)

        attack_class = "Uncertain"
        confidence   = 0.0

        if is_anomaly:
            # ip_proto fix: per-flow ip_proto ALWAYS overrides switch-level
            # Restore prior confident class if available and RF returns Uncertain
            # dominant proto. Switch aggregate gets polluted when multiple attack
            # types run simultaneously (e.g. UDP + ICMP campaign) — the dominant
            # switch proto may be ICMP even for a UDP flow, causing misclassification.
            # Per-flow ip_proto from OVS flow match is always exact — use it.
            rf_switch = dict(switch_stats) if switch_stats else {}
            _flow_proto = int((flow_stats or {}).get("ip_proto", 0))
            if _flow_proto:
                # Force override regardless of what switch_stats says
                rf_switch["ip_proto"] = _flow_proto
                log.debug("ip_proto override: %s → proto=%d (flow) over switch dominant",
                          src_ip, _flow_proto)
            rf_vec              = rf_pipeline.extract_rf_features(rf_switch)
            attack_class, confidence = rf_pipeline.run_rf_inference(rf_vec)

            # Guard: if re-run returns Uncertain but we had a prior confident
            # classification (cache expired mid-attack), restore the prior class.
            # Prevents label flipping during sustained attacks with mixed switch stats.
            if attack_class == "Uncertain" and _prior_class not in (None, "Uncertain") and _prior_conf >= 0.70:
                log.debug("RF re-run returned Uncertain — restoring prior class %s (conf=%.1f%%)",
                          _prior_class, _prior_conf * 100)
                attack_class = _prior_class
                confidence   = _prior_conf

        # ── Diagnostic log — visible in backend terminal for every evaluated flow ──
        pps_display = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
        sw_pps      = float(flow_stats.get("switch_delta_pps", 0.0)) if flow_stats else 0.0
        conf_display = f"{confidence*100:.1f}%" if is_anomaly else "—"
        log.info(
            "[SCAN] %-15s  pps=%7.1f  sw_delta=%7.1f  IF=%.4f(thr=%.4f)  "
            "anomaly=%-5s  RF=%-12s  conf=%s",
            src_ip, pps_display, sw_pps, if_score, _effective_threshold,
            str(is_anomaly), attack_class if is_anomaly else "—", conf_display
        )
        # Push to scan log buffer for /api/debug/flows endpoint
        try:
            from backend.pipeline.decision_engine import push_scan_result
            push_scan_result(
                src_ip, pps_display, sw_pps,
                if_score, _effective_threshold, is_anomaly,
                attack_class, confidence
            )
        except Exception:
            pass

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