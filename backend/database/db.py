import sqlite3
import os
import threading
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

        -- ── detection_features — all IF + RF features + binary attack-type flags ──
        CREATE TABLE IF NOT EXISTS detection_features (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            if_score    REAL    NOT NULL,
            is_anomaly  INTEGER NOT NULL,
            attack_class TEXT   NOT NULL,
            confidence  REAL    NOT NULL,

            -- IF features (feature_contract.json)
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

            -- RF / switch-level features (rf_sdn_feature_contract.json)
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

            -- Binary attack-type flags (exactly one = 1)
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

        -- ── quarantine_state — persists active mitigations across restarts ──
        CREATE TABLE IF NOT EXISTS quarantine_state (
            src_ip        TEXT PRIMARY KEY,
            phase         INTEGER NOT NULL,
            attack_vector TEXT    NOT NULL,
            if_score      REAL    NOT NULL,
            confidence    REAL    NOT NULL,
            action_taken  TEXT    NOT NULL,
            permanent     INTEGER NOT NULL DEFAULT 0,
            updated_at    TEXT    NOT NULL
        );

        -- ── global_counters — single-row all-time accumulator ─────────────────
        -- Never resets. Written to on every pipeline cycle so stats survive
        -- server restarts. Row id=1 is always the one and only record.
        CREATE TABLE IF NOT EXISTS global_counters (
            id               INTEGER PRIMARY KEY CHECK (id = 1),
            total_packets    INTEGER NOT NULL DEFAULT 0,
            malicious_dropped INTEGER NOT NULL DEFAULT 0,
            normal_packets   INTEGER NOT NULL DEFAULT 0,
            false_positives  INTEGER NOT NULL DEFAULT 0
        );

        -- Seed the single row so UPDATE always finds a target
        INSERT OR IGNORE INTO global_counters (id, total_packets, malicious_dropped, normal_packets, false_positives)
        VALUES (1, 0, 0, 0, 0);
    """)


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


def increment_global_counters(
    total: int = 0,
    malicious: int = 0,
    normal: int = 0,
    fp: int = 0,
) -> None:
    """Atomically add to the persistent all-time counters.

    Call this from decision_engine (or wherever traffic_summary is written)
    to keep global_counters in sync alongside traffic_summary.

    Example usage in decision_engine::

        from backend.database.db import increment_global_counters
        increment_global_counters(total=1, malicious=1)
    """
    execute("""
        UPDATE global_counters
        SET total_packets     = total_packets     + ?,
            malicious_dropped = malicious_dropped + ?,
            normal_packets    = normal_packets    + ?,
            false_positives   = false_positives   + ?
        WHERE id = 1
    """, (total, malicious, normal, fp))