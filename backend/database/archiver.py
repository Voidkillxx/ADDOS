import time
import threading
import logging
from backend.database.db import transaction, query

log = logging.getLogger(__name__)

ARCHIVE_AFTER_HOURS = 24
ARCHIVE_INTERVAL_S  = 3600   # once per hour


def _archive_old_events() -> int:
    """Move events older than ARCHIVE_AFTER_HOURS from hot table to archive.

    C3 fix: uses transaction() context manager for a real atomic operation.
    Previously execute("BEGIN") auto-committed immediately because every
    db.execute() calls conn.commit() — making the old BEGIN/ROLLBACK a no-op
    and leaving rows in both tables or losing them entirely on a mid-loop crash.
    """
    cutoff = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(time.time() - ARCHIVE_AFTER_HOURS * 3600)
    )

    old_rows = query(
        "SELECT * FROM mitigation_events WHERE timestamp < ?", (cutoff,)
    )

    if not old_rows:
        return 0

    try:
        with transaction() as conn:
            for row in old_rows:
                conn.execute("""
                    INSERT INTO mitigation_events_archive
                        (timestamp, src_ip, predicted_class, attack_vector,
                         confidence, priority, action_taken, if_score, phase, is_manual)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row["timestamp"], row["src_ip"], row["predicted_class"],
                    row["attack_vector"], row["confidence"], row["priority"],
                    row["action_taken"], row.get("if_score"), row.get("phase"),
                    row.get("is_manual", 0),
                ))
            conn.execute(
                "DELETE FROM mitigation_events WHERE timestamp < ?", (cutoff,)
            )
        log.info("Archived %d mitigation events (older than %s)",
                 len(old_rows), cutoff)
    except Exception:
        log.exception("Archiver failed — rolled back")
        return 0

    return len(old_rows)


def _archiver_loop() -> None:
    while True:
        time.sleep(ARCHIVE_INTERVAL_S)
        try:
            _archive_old_events()
        except Exception:
            log.exception("Archiver loop error")


def start() -> None:
    t = threading.Thread(target=_archiver_loop, name="db-archiver", daemon=True)
    t.start()
    log.info("DB archiver started (interval=%ds, cutoff=%dh)",
             ARCHIVE_INTERVAL_S, ARCHIVE_AFTER_HOURS)