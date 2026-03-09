from flask import Blueprint, jsonify, request
from backend.mitigation.state_machine import state_machine

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
    """Flush all non-permanent quarantine entries immediately.
    Use this to release legit hosts that were false-positived without restarting.
    Permanent (manually blocked) entries are preserved.
    """
    cleared = state_machine.clear_all_non_permanent()
    return jsonify({"status": "ok", "cleared": cleared})