from flask import Blueprint, jsonify
from backend.pipeline.decision_engine import get_stats, get_scan_log
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader

bp = Blueprint("stats", __name__)


@bp.get("/api/stats")
def stats():
    session = get_stats()
    raw     = get_raw_counts()

    raw_total = raw["raw_total"]
    malicious = session.get("malicious_dropped", 0)

    # C2 fix: Normal Traffic = Total − Malicious (Option A, approved).
    # Previously stats.py served raw["raw_normal"] which equalled raw_total
    # because zmq_receiver set _raw_normal_pkts = delta_pkts for ALL traffic
    # and the promised "DE corrects if attack" correction was never implemented.
    # The result: Normal Traffic card always matched Total Traffic exactly.
    # Now computed directly from sources that are already accurate.
    normal = max(raw_total - malicious, 0)

    fp_rate = session.get("fp_rate", 0.0)

    return jsonify({
        # Summary cards
        "total_packets":     raw_total,
        "malicious_dropped": malicious,
        "normal_packets":    normal,

        # Live chart deltas (same sources — cards and chart now always match)
        "live_total":        raw_total,
        "live_malicious":    malicious,
        "live_normal":       normal,

        # Session metrics
        "active_threats":    session.get("active_threats",  0),
        "avg_latency_ms":    session.get("avg_latency_ms",  0),
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


@bp.get("/api/debug/flows")
def debug_flows():
    """Last 200 flow evaluations — shows IF score, PPS, RF class, confidence.

    Use this during an attack to verify the pipeline is running and see
    exactly what scores each IP is getting.  Refreshes every 2s from the
    frontend or poll manually with:
        curl http://127.0.0.1:5000/api/debug/flows | python3 -m json.tool
    """
    return jsonify(get_scan_log())