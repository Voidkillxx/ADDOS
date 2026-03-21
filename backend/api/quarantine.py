from flask import Blueprint, jsonify, request
from backend.mitigation.state_machine import state_machine
from backend.pipeline.decision_engine import record_false_positive, drain_pending_restores

bp = Blueprint("quarantine", __name__)


@bp.get("/api/quarantine_list")
def quarantine_list():
    return jsonify(state_machine.get_active_list())


@bp.post("/api/quarantine/release")
def release():
    src_ip = (request.get_json(silent=True) or {}).get("src_ip", "").strip()
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400

    released = state_machine.manual_release(src_ip)
    if not released:
        return jsonify({"error": f"{src_ip} not found in active list"}), 404

    # FP rate fix: manual release = operator ground truth that this was a FP.
    # Increments in-memory fp counter and buffers fp=1 into traffic_summary
    # (for PDF report).  Also queues IP for auto baseline restoration.
    record_false_positive(src_ip)

    return jsonify({"status": "released", "src_ip": src_ip})


@bp.post("/api/quarantine/block")
def block():
    src_ip = (request.get_json(silent=True) or {}).get("src_ip", "").strip()
    if not src_ip:
        return jsonify({"error": "src_ip required"}), 400

    state_machine.manual_block(src_ip)
    return jsonify({"status": "blocked", "src_ip": src_ip})


@bp.post("/api/quarantine/clear_all")
def clear_all():
    """Flush all non-permanent quarantine entries immediately."""
    cleared = state_machine.clear_all_non_permanent()
    return jsonify({"status": "ok", "cleared": cleared})


# ── Feature 2: Auto-restoration polling endpoint ──────────────────────────────

@bp.get("/api/pending_restores")
def pending_restores():
    """Returns and clears IPs that need baseline traffic restarted.

    Polled by topology.py restore-poller thread every 5 seconds.
    When an IP appears here, Mininet restarts its baseline ping at 0.33 pps.
    """
    ips = drain_pending_restores()
    return jsonify({"ips": ips})