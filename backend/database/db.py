import sqlite3
import os
import threading
from contextlib import contextmanager
from backend.config import DB_PATH

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
                _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                _conn.execute("PRAGMA journal_mode=WAL")
                _conn.execute("PRAGMA synchronous=NORMAL")
                _init_schema(_conn)
                _migrate(_conn)
                _conn.commit()
    return _conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS mitigation_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            predicted_class TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL,
            action_taken    TEXT    NOT NULL,
            if_score        REAL,
            phase           TEXT,
            is_manual       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS mitigation_events_archive (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            predicted_class TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL,
            action_taken    TEXT    NOT NULL,
            if_score        REAL,
            phase           TEXT,
            is_manual       INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_summary (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp             TEXT    NOT NULL,
            total_flows_observed  INTEGER DEFAULT 0,
            threats_mitigated     INTEGER DEFAULT 0,
            true_negatives_passed INTEGER DEFAULT 0,
            false_positives       INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts    ON mitigation_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ip    ON mitigation_events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_summary_ts   ON traffic_summary(timestamp);
        CREATE INDEX IF NOT EXISTS idx_archive_ts   ON mitigation_events_archive(timestamp);

        CREATE TABLE IF NOT EXISTS detection_features (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            if_score    REAL    NOT NULL,
            is_anomaly  INTEGER NOT NULL,
            attack_class TEXT   NOT NULL,
            confidence  REAL    NOT NULL,

            flow_duration_sec        REAL,
            flow_duration_nsec       REAL,
            idle_timeout             INTEGER,
            hard_timeout             INTEGER,
            flags                    INTEGER,
            packet_count             INTEGER,
            byte_count               INTEGER,
            packet_count_per_second  REAL,
            packet_count_per_nsecond REAL,
            byte_count_per_second    REAL,
            byte_count_per_nsecond   REAL,
            flow_duration_total_ns   REAL,
            bytes_per_packet         REAL,
            pkt_byte_rate_ratio      REAL,

            disp_pakt            INTEGER,
            disp_byte            INTEGER,
            mean_pkt             REAL,
            mean_byte            REAL,
            avg_durat            REAL,
            avg_flow_dst         INTEGER,
            rate_pkt_in          REAL,
            disp_interval        REAL,
            gfe                  INTEGER,
            g_usip               INTEGER,
            rfip                 INTEGER,
            gsp                  INTEGER,
            ip_diversity_ratio   REAL,
            byte_per_interval    REAL,
            pkt_per_interval     REAL,
            flow_entry_ratio     REAL,
            mean_pkt_byte_ratio  REAL,

            flag_syn_flood   INTEGER NOT NULL DEFAULT 0,
            flag_icmp_flood  INTEGER NOT NULL DEFAULT 0,
            flag_udp_flood   INTEGER NOT NULL DEFAULT 0,
            flag_normal      INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_df_src_ip
            ON detection_features (src_ip);
        CREATE INDEX IF NOT EXISTS idx_df_timestamp
            ON detection_features (timestamp);
        CREATE INDEX IF NOT EXISTS idx_df_attack_class
            ON detection_features (attack_class);

        -- quarantine_state — block_expires_at TEXT added for TTL persistence.
        -- NULL = permanent (manual block). ISO timestamp = auto-block expiry.
        CREATE TABLE IF NOT EXISTS quarantine_state (
            src_ip           TEXT PRIMARY KEY,
            phase            INTEGER NOT NULL,
            attack_vector    TEXT    NOT NULL,
            if_score         REAL    NOT NULL,
            confidence       REAL    NOT NULL,
            action_taken     TEXT    NOT NULL,
            permanent        INTEGER NOT NULL DEFAULT 0,
            updated_at       TEXT    NOT NULL,
            block_expires_at TEXT
        );

        -- ip_attack_history: one row per IP per attack session.
        -- Written when an IP is unblocked (TTL expiry, manual release, or escalation).
        -- Used for history view and report generation by date range.
        CREATE TABLE IF NOT EXISTS ip_attack_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip          TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            if_score        REAL    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL DEFAULT 'Low',
            phase_reached   INTEGER NOT NULL DEFAULT 1,
            first_seen      TEXT    NOT NULL,
            unblocked_at    TEXT    NOT NULL,
            duration_sec    INTEGER NOT NULL DEFAULT 0,
            unblock_reason  TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_history_ip
            ON ip_attack_history (src_ip);
        CREATE INDEX IF NOT EXISTS idx_history_unblocked
            ON ip_attack_history (unblocked_at);
        CREATE INDEX IF NOT EXISTS idx_history_date
            ON ip_attack_history (date(unblocked_at));

        CREATE TABLE IF NOT EXISTS global_counters (
            id               INTEGER PRIMARY KEY CHECK (id = 1),
            total_packets    INTEGER NOT NULL DEFAULT 0,
            malicious_dropped INTEGER NOT NULL DEFAULT 0,
            normal_packets   INTEGER NOT NULL DEFAULT 0,
            false_positives  INTEGER NOT NULL DEFAULT 0
        );

        INSERT OR IGNORE INTO global_counters
            (id, total_packets, malicious_dropped, normal_packets, false_positives)
        VALUES (1, 0, 0, 0, 0);
    """)


def _migrate(conn: sqlite3.Connection) -> None:
    """Safe schema migrations for existing databases.

    Each ALTER TABLE is wrapped in try/except so re-running on a fresh DB
    (which already has the column from _init_schema) is a no-op.
    """
    # H5 fix: add block_expires_at to existing quarantine_state tables.
    try:
        conn.execute(
            "ALTER TABLE quarantine_state ADD COLUMN block_expires_at TEXT"
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass   # column already exists — normal on fresh install or re-run


# ---------------------------------------------------------------------------
# C3 fix: atomic transaction context manager
# ---------------------------------------------------------------------------

@contextmanager
def transaction():
    """Context manager for multi-statement atomic transactions.

    Usage::

        with transaction() as conn:
            conn.execute("INSERT INTO ...", (...))
            conn.execute("DELETE FROM ...", (...))
        # commits on __exit__, rolls back on exception

    Holds _lock for the duration — do not nest with execute() or query().
    """
    conn = get_connection()
    with _lock:
        conn.execute("BEGIN")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    conn = get_connection()
    with _lock:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur


def executemany(sql: str, params_list: list) -> None:
    conn = get_connection()
    with _lock:
        conn.executemany(sql, params_list)
        conn.commit()


def query(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_connection()
    with _lock:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.row_factory = None
        return rows