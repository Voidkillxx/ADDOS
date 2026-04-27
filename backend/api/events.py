import time
import json
from flask import Blueprint, Response, jsonify, request
from backend.pipeline.decision_engine import drain_sse_events
from backend.database.db import query

bp = Blueprint("events", __name__)


@bp.get("/api/events")
def events():
    def _stream():
        while True:
            new_events = drain_sse_events()
            for event in new_events:
                yield f"data: {json.dumps(event)}\n\n"
            time.sleep(0.5)

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.get("/api/recent_events")
def recent_events():
    """Return the most recent mitigation log entries from the DB.

    Called by the frontend on page load and SSE reconnect to replay events
    that were fired before the browser connected (or while it was disconnected).

    Query params:
        limit  -- max rows to return (default 100, max 500)
        since  -- optional ISO timestamp; only return rows strictly after this time
    """
    limit = min(int(request.args.get("limit", 100)), 500)
    since = request.args.get("since", "")

    if since:
        rows = query("""
            SELECT timestamp, src_ip, predicted_class, attack_vector,
                   confidence, priority, action_taken
            FROM mitigation_events
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (since, limit))
    else:
        rows = query("""
            SELECT timestamp, src_ip, predicted_class, attack_vector,
                   confidence, priority, action_taken
            FROM mitigation_events
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    events_out = []
    for r in rows:
        conf = r["confidence"]
        # DB stores raw float 0-1; format to "87.8%" to match live SSE format
        if isinstance(conf, (int, float)):
            conf_str = f"{float(conf) * 100:.1f}%"
        else:
            conf_str = str(conf) if conf else "---"

        events_out.append({
            "timestamp":       (r["timestamp"] or "").strip(),
            "src_ip":          (r["src_ip"] or "").strip(),
            "predicted_class": r["predicted_class"],
            "attack_vector":   r["attack_vector"],
            "confidence":      conf_str,
            "priority":        r["priority"],
            "action_taken":    r["action_taken"],
        })

    # Reverse to chronological order (oldest first) so frontend prepends correctly
    events_out.reverse()
    return jsonify(events_out)