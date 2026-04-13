import time
import json
from flask import Blueprint, Response
from backend.pipeline.decision_engine import drain_sse_events

bp = Blueprint("events", __name__)


@bp.get("/api/events")
def events():
    def _stream():
        # M8 fix: session_log was accumulated (up to 100 entries) and trimmed,
        # but was never yielded to the client — only new_events were sent.
        # The server-side cap was dead code; the real cap is MAX_LOG=100 in
        # main.js.  Reconnecting SSE clients also got no replay, so the
        # accumulated list served no purpose at all.  Removed.
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