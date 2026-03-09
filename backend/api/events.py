import time
import json
from flask import Blueprint, Response
from backend.pipeline.decision_engine import drain_sse_events

bp = Blueprint("events", __name__)

# Audit log cap — only the latest 100 events are kept per SSE session
_AUDIT_CAP = 100


@bp.get("/api/events")
def events():
    def _stream():
        session_log = []
        while True:
            new_events = drain_sse_events()
            if new_events:
                session_log.extend(new_events)
                # Enforce 100-event cap — discard oldest beyond limit
                if len(session_log) > _AUDIT_CAP:
                    session_log = session_log[-_AUDIT_CAP:]
                for event in new_events:
                    yield f"data: {json.dumps(event)}\n\n"
            # UI batch interval — push every 500ms per spec
            time.sleep(0.5)

    return Response(
        _stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind proxy
        },
    )