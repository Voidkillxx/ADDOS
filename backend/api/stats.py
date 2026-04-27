from flask import Blueprint, jsonify
from backend.pipeline.decision_engine import get_stats, get_scan_log
from backend.pipeline.flow_tracker import tracker
from backend.transport.zmq_receiver import get_raw_counts
from backend.models import loader
from backend.database.db import query

bp = Blueprint("stats", __name__)


@bp.get("/api/stats")
def stats():
    session = get_stats()
    raw     = get_raw_counts()

    raw_total = raw["raw_total"]
    malicious = session.get("malicious_dropped", 0)

    # Use whichever counter is larger — raw_total from ZMQ counts raw packet
    # deltas but resets on reconnect and misses low-pps baseline flows.
    # session total_packets counts every on_result() call reliably.
    # Taking the max ensures the UI always shows the most accurate count.
    effective_total = max(raw_total, session.get("total_packets", 0))

    # C2 fix: Normal Traffic = Total − Malicious (Option A, approved).
    normal = max(effective_total - malicious, 0)

    fp_rate = session.get("fp_rate", 0.0)

    return jsonify({
        # Summary cards
        "total_packets":     effective_total,
        "malicious_dropped": malicious,
        "normal_packets":    normal,

        # Live chart deltas (same sources — cards and chart now always match)
        "live_total":        effective_total,
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


@bp.get("/api/ip_detail/<path:src_ip>")
def ip_detail(src_ip: str):
    """Return full threat analysis for a single IP.

    Priority:
      1. Live: tracker.get_flow() + tracker.get_cached() for real-time data
      2. DB:   detection_features (real feature values) + mitigation_events
               + ip_attack_history for state metadata
    Returns 404 only when no data exists anywhere.
    """
    src_ip = src_ip.strip()

    # ── 1. Live flow tracker ──────────────────────────────────────
    flow   = tracker.get_flow(src_ip)
    cached = tracker.get_cached(src_ip)

    if flow and cached:  # both required — cache miss means stale, fall to DB
        fs = flow.flow_stats or {}
        # syn_ratio: SYN flags / total packets
        flags     = fs.get("flags", 0)
        pkt_count = max(int(fs.get("packet_count", 0)), 1)
        syn_ratio = (flags & 0x02) / pkt_count if flags else 0.0

        return jsonify({
            "src_ip": src_ip,
            "features": {
                "pkt_count":     fs.get("packet_count", 0),
                "syn_ratio":     round(syn_ratio, 4),
                "pps":           fs.get("packet_count_per_second", 0),
                "byte_rate":     fs.get("byte_count_per_second", 0),
                "active_flows":  tracker.active_count(),
                "sw_delta":      fs.get("sw_delta", 0),
                "inter_arrival": fs.get("inter_arrival", 0),
                "unique_ports":  fs.get("unique_ports", 0),
                "duration_sec":  fs.get("flow_duration_sec", 0),
            },
            "ml": {
                "if_score":     cached.if_score,
                "is_anomaly":   cached.is_anomaly,
                "attack_class": cached.attack_class,
                "confidence":   round(cached.confidence * 100, 1),
            },
            "state": {
                "phase":         "—",
                "priority":      "—",
                "action_taken":  "—",
                "offence_count": 0,
                "ban_level":     0,
                "first_seen":    None,
            },
            "thresholds": {
                "if_threshold": loader.if_threshold,
                "rf_conf_gate": loader.rf_conf_gate,
            },
            "phase_history": [],  # live IP — no completed phase history yet
        })

    # ── 2. DB fallback ────────────────────────────────────────────
    # 2a. Most recent mitigation event for IF score / action / phase
    ev_rows = query("""
        SELECT timestamp, predicted_class, attack_vector, confidence,
               if_score, phase, priority, action_taken
        FROM mitigation_events
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    if not ev_rows:
        ev_rows = query("""
            SELECT timestamp, predicted_class, attack_vector, confidence,
                   if_score, phase, priority, action_taken
            FROM mitigation_events_archive
            WHERE src_ip = ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip,))
    if not ev_rows:
        return jsonify({"error": "No data found for this IP"}), 404

    ev       = ev_rows[0]
    if_score = ev.get("if_score") or 0.0
    conf_raw = ev.get("confidence") or 0.0
    conf_pct = round(conf_raw * 100, 1) if conf_raw <= 1.0 else round(conf_raw, 1)

    # 2b. Real feature values from detection_features (most recent row)
    feat_rows = query("""
        SELECT packet_count, packet_count_per_second, byte_count_per_second,
               flow_duration_sec, flags, disp_pakt, disp_interval,
               gsp, gfe, mean_pkt, mean_byte
        FROM detection_features
        WHERE src_ip = ?
        ORDER BY timestamp DESC LIMIT 1
    """, (src_ip,))
    feat = feat_rows[0] if feat_rows else {}

    pkt_count = max(int(feat.get("packet_count", 0) or 0), 1)
    flags     = int(feat.get("flags", 0) or 0)
    syn_ratio = round((flags & 0x02) / pkt_count, 4) if flags else 0.0
    gfe       = feat.get("gfe") or 0
    gsp       = max(feat.get("gsp") or 1, 1)
    unique_ports = int(gfe / gsp) if gsp else 0

    # inter_arrival: disp_interval / disp_pakt (avg gap between packets)
    disp_pakt     = max(feat.get("disp_pakt") or 1, 1)
    disp_interval = feat.get("disp_interval") or 0
    inter_arrival = round(disp_interval / disp_pakt, 6)

    # 2c. ip_attack_history for offence/ban/phase metadata
    hist = query("""
        SELECT offence_count, ban_level, phase_reached, first_seen, priority
        FROM ip_attack_history
        WHERE src_ip = ?
        ORDER BY unblocked_at DESC LIMIT 1
    """, (src_ip,))
    h = hist[0] if hist else {}

    # 2d. Phase history — all distinct phase transitions for this IP
    phase_rows = query("""
        SELECT timestamp, phase, action_taken, attack_vector
        FROM mitigation_events
        WHERE src_ip = ?
        ORDER BY timestamp ASC
    """, (src_ip,))
    if not phase_rows:
        phase_rows = query("""
            SELECT timestamp, phase, action_taken, attack_vector
            FROM mitigation_events_archive
            WHERE src_ip = ?
            ORDER BY timestamp ASC
        """, (src_ip,))
    # Deduplicate: keep first occurrence of each (phase, action_taken) pair
    seen_phases = set()
    phase_history = []
    for pr in phase_rows:
        key = (pr.get("phase"), pr.get("action_taken"))
        if key not in seen_phases:
            seen_phases.add(key)
            phase_history.append({
                "timestamp":    pr.get("timestamp"),
                "phase":        pr.get("phase") or "—",
                "action_taken": pr.get("action_taken") or "—",
                "attack_vector": pr.get("attack_vector") or "—",
            })

    return jsonify({
        "src_ip": src_ip,
        "features": {
            "pkt_count":     feat.get("packet_count", 0) or 0,
            "syn_ratio":     syn_ratio,
            "pps":           feat.get("packet_count_per_second", 0) or 0,
            "byte_rate":     feat.get("byte_count_per_second", 0) or 0,
            "active_flows":  gfe,
            "sw_delta":      round(feat.get("mean_pkt") or 0, 2),
            "inter_arrival": inter_arrival,
            "unique_ports":  unique_ports,
            "duration_sec":  feat.get("flow_duration_sec", 0) or 0,
        },
        "ml": {
            "if_score":     if_score,
            "is_anomaly":   True,
            "attack_class": ev.get("attack_vector") or "—",
            "confidence":   conf_pct,
        },
        "state": {
            "phase":         ev.get("phase") or h.get("phase_reached") or "—",
            "priority":      ev.get("priority") or h.get("priority") or "—",
            "action_taken":  ev.get("action_taken") or "—",
            "offence_count": h.get("offence_count", 0),
            "ban_level":     h.get("ban_level", 0),
            "first_seen":    h.get("first_seen"),
        },
        "phase_history": phase_history,
        "thresholds": {
            "if_threshold": loader.if_threshold,
            "rf_conf_gate": loader.rf_conf_gate,
        },
    })