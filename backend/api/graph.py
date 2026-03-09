import time
import datetime
from flask import Blueprint, jsonify, request
from backend.database.db import query
from backend.config import GRAPH_BUCKET_COUNT

bp = Blueprint("graph", __name__)

_RANGE_SECONDS = {
    "1hr":   3600,
    "12hr":  43200,
    "24hr":  86400,
}


def _session_start_ts() -> str:
    """Returns the backend process start time as a SQL-comparable string."""
    # Stored at import time when the module is first loaded
    return _BACKEND_START


_BACKEND_START = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@bp.get("/api/graph_history")
def graph_history():
    range_key = request.args.get("range", "1hr")

    now_dt = datetime.datetime.now()

    if range_key == "session":
        start_dt = datetime.datetime.strptime(_BACKEND_START, "%Y-%m-%d %H:%M:%S")
    elif range_key in _RANGE_SECONDS:
        start_dt = now_dt - datetime.timedelta(seconds=_RANGE_SECONDS[range_key])
    else:
        return jsonify({"error": "Invalid range"}), 400

    start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")
    end_str   = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    rows = query("""
        SELECT timestamp, total_flows_observed, threats_mitigated, true_negatives_passed
        FROM traffic_summary
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC
    """, (start_str, end_str))

    buckets = _bucket_rows(rows, start_dt, now_dt, GRAPH_BUCKET_COUNT)
    return jsonify(buckets)


def _bucket_rows(rows: list[dict],
                 start_dt: datetime.datetime,
                 end_dt: datetime.datetime,
                 n_buckets: int) -> list[dict]:
    """Aggregate rows into n_buckets evenly-spaced time intervals."""
    total_seconds = max((end_dt - start_dt).total_seconds(), 1)
    bucket_size_s = total_seconds / n_buckets

    # Initialise empty buckets
    buckets = []
    for i in range(n_buckets):
        bucket_start = start_dt + datetime.timedelta(seconds=i * bucket_size_s)
        buckets.append({
            "timestamp":  bucket_start.strftime("%Y-%m-%d %H:%M:%S"),
            "incoming":   0,
            "blocked":    0,
            "forwarded":  0,
        })

    for row in rows:
        try:
            row_dt = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        offset_s = (row_dt - start_dt).total_seconds()
        idx = min(int(offset_s / bucket_size_s), n_buckets - 1)
        buckets[idx]["incoming"]  += row["total_flows_observed"]
        buckets[idx]["blocked"]   += row["threats_mitigated"]
        buckets[idx]["forwarded"] += row["true_negatives_passed"]

    return buckets