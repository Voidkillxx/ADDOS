from flask import Blueprint, jsonify
from backend.pipeline.decision_engine import get_stats
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader
from backend.database.db import query

bp = Blueprint("stats", __name__)


@bp.get("/api/stats")
def stats():
    # ── Real-time in-memory stats from decision engine ────────────────────────
    session = get_stats()

    # ── Raw packet counters from ZMQ receiver (for live chart) ───────────────
    raw = get_raw_counts()

    # ── All-time persistent totals from DB (for summary cards only) ──────────
    rows = query("""
        SELECT
            COALESCE(SUM(total_flows_observed),   0) AS total_packets,
            COALESCE(SUM(threats_mitigated),       0) AS malicious_dropped,
            COALESCE(SUM(true_negatives_passed),   0) AS normal_packets,
            COALESCE(SUM(false_positives),         0) AS fp_total
        FROM traffic_summary
    """)

    db        = rows[0] if rows else {}
    total     = max(int(db.get("total_packets",     0)), 1)
    malicious = int(db.get("malicious_dropped",     0))
    normal    = int(db.get("normal_packets",        0))

    # ── FP rate: ALWAYS use in-memory session value ───────────────────────────
    # The DB-based formula (fp / (fp + TN)) breaks because baseline traffic is
    # filtered in zmq_receiver before reaching the ML pipeline — so
    # true_negatives_passed in the DB is always 0, making the DB rate = 100%.
    #
    # The session fp_rate from decision_engine is correct:
    #   fp_rate = false_positives_this_session / total_ml_processed_this_session
    # This resets to 0 on restart and only counts flows that actually went
    # through the ML pipeline, giving a meaningful real-time accuracy metric.
    fp_rate = session.get("fp_rate", 0.0)

    # ── Use raw counters for BOTH cards and graph so they always match ───────
    # Cards (DB-based) lag behind by up to 5s and use different units than
    # the graph (raw packet deltas) — causing the visible mismatch.
    # Solution: cards use raw_total/raw_normal from zmq_receiver (same source
    # as graph). malicious_dropped comes from session (decision_engine) which
    # is incremented only when RF confirms a real attack.
    return jsonify({
        # ── Summary cards — use same source as graph ──────────────────────────
        "total_packets":     raw["raw_total"],
        "malicious_dropped": session.get("malicious_dropped", 0),
        "normal_packets":    raw["raw_normal"],

        # ── Live chart deltas ─────────────────────────────────────────────────
        "live_total":        raw["raw_total"],
        "live_malicious":    session.get("malicious_dropped", 0),
        "live_normal":       raw["raw_normal"],

        # ── Live session metrics ──────────────────────────────────────────────
        "active_threats":    session.get("active_threats",    0),
        "avg_latency_ms":    session.get("avg_latency_ms",    0),
        "fp_rate":           fp_rate,
    })


@bp.get("/api/model_info")
def model_info():
    loader.require_loaded()
    return jsonify({
        "if_accuracy":  None,
        "rf_accuracy":  None,
        "if_threshold": loader.if_threshold,
        "rf_conf_gate": loader.rf_conf_gate,
        "if_features":  loader.if_features,
        "rf_features":  loader.rf_features,
        "rf_classes":   loader.rf_classes,
    })