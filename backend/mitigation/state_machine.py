import time
import datetime
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional
from backend.database import writer

log = logging.getLogger(__name__)

PHASE1_DURATION    = 30.0
PHASE2_DURATION    = 60.0
PROBATION_DURATION = 120.0

# Feature 1: TTL for system auto-blocks. Maximum 1 hour, then auto-unblock.
# Manual blocks (operator-initiated) are permanent (ttl_expires_at=None).
BLOCK_TTL_SECONDS = 3600

MIN_QUARANTINE_CONFIDENCE = 0.60

PHASE_LABELS = {
    1: "Phase 1 — Quarantined",
    2: "Phase 2 — Rate Limited",
    3: "Phase 3 — Blocked",
    4: "Probation",
}


@dataclass
class IpState:
    src_ip:         str
    phase:          int   = 1
    attack_vector:  str   = "Uncertain"
    if_score:       float = 0.0
    confidence:     float = 0.0
    phase_entered:  float = field(default_factory=time.monotonic)
    action_taken:   str   = "Quarantined"
    permanent:      bool  = False
    # H5 fix: TTL expiry in monotonic time (in-memory only).
    # The actual wall-clock expiry is persisted in quarantine_state.block_expires_at
    # so it survives backend restarts.  None = manual permanent block.
    ttl_expires_at: Optional[float] = None

    def phase_label(self) -> str:
        return PHASE_LABELS.get(self.phase, "Unknown")

    def time_in_phase_sec(self) -> float:
        return time.monotonic() - self.phase_entered

    def to_api_dict(self) -> dict:
        d = {
            "src_ip":            self.src_ip,
            "phase":             self.phase_label(),
            "attack_vector":     self.attack_vector,
            "if_score":          round(self.if_score, 4),
            "confidence":        f"{self.confidence * 100:.1f}%",
            "time_in_phase_sec": int(self.time_in_phase_sec()),
        }
        if self.ttl_expires_at is not None:
            d["ttl_remaining_sec"] = max(0, int(self.ttl_expires_at - time.monotonic()))
        return d


class StateMachine:

    def __init__(self):
        self._lock      = threading.Lock()
        self._states: dict[str, IpState] = {}
        self._commander = None

    def set_commander(self, commander) -> None:
        self._commander = commander

    # ------------------------------------------------------------------
    # Startup restore
    # ------------------------------------------------------------------

    def restore_from_db(self) -> None:
        """Load persisted quarantine entries and re-apply OFP rules.

        H5 fix: block_expires_at is now used to correctly restore TTLs.
        - Non-permanent phase-1/2 entries are purged (stale FPs from last session).
        - Permanent phase-3 manual blocks are restored without expiry.
        - Phase-3 auto-blocks (permanent=True, block_expires_at set) are restored
          with their remaining TTL.  If the TTL already expired during downtime,
          the entry is cleared immediately.
        """
        rows = writer.load_quarantine_states()
        if not rows:
            return

        log.info("Restoring quarantine entries from DB (%d total)...", len(rows))
        restored = 0
        purged   = 0
        expired  = 0
        now_wall = datetime.datetime.now()

        with self._lock:
            for r in rows:
                src_ip          = r["src_ip"]
                permanent       = bool(r.get("permanent", False))
                block_expires_at = r.get("block_expires_at")

                # Non-permanent (phase-1 or phase-2) entries are stale FPs —
                # purge them so previously wrongly-blocked hosts are released.
                if not permanent:
                    self._push_command(src_ip, "clear")
                    writer.delete_quarantine_state(src_ip)
                    log.info("Purged stale FP on restore: %s", src_ip)
                    purged += 1
                    continue

                # Permanent phase-3: check if TTL expired during downtime
                if block_expires_at is not None:
                    try:
                        exp_dt = datetime.datetime.strptime(
                            block_expires_at, "%Y-%m-%d %H:%M:%S"
                        )
                        remaining_s = (exp_dt - now_wall).total_seconds()
                    except ValueError:
                        remaining_s = 0  # malformed timestamp → treat as expired

                    if remaining_s <= 0:
                        # TTL expired while backend was offline — release now
                        self._push_command(src_ip, "clear")
                        writer.delete_quarantine_state(src_ip)
                        log.info("TTL expired during downtime, released: %s", src_ip)
                        expired += 1
                        continue

                    # Restore with remaining TTL
                    ttl_expires_at = time.monotonic() + remaining_s
                    ttl_for_cmd    = int(remaining_s)
                else:
                    # Manual permanent block — no TTL
                    ttl_expires_at = None
                    ttl_for_cmd    = None

                state = IpState(
                    src_ip        = src_ip,
                    phase         = r["phase"],
                    attack_vector = r.get("attack_vector", "Uncertain"),
                    if_score      = float(r.get("if_score", 0) or 0),
                    confidence    = float(r.get("confidence", 0) or 0),
                    action_taken  = r.get("action_taken", "Quarantined"),
                    permanent     = permanent,
                    ttl_expires_at = ttl_expires_at,
                )
                self._states[src_ip] = state
                _action_map = {1: "quarantine", 2: "rate_limit", 3: "block"}
                self._push_command(
                    src_ip,
                    _action_map.get(r["phase"], "quarantine"),
                    ttl=ttl_for_cmd,
                )
                restored += 1

        log.info(
            "Quarantine restore — %d restored, %d stale purged, %d TTL-expired",
            restored, purged, expired,
        )

    # ------------------------------------------------------------------
    # Automatic progression
    # ------------------------------------------------------------------

    def on_detection(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float) -> str:
        with self._lock:
            state = self._states.get(src_ip)

            if state and state.permanent and state.ttl_expires_at is None:
                # Truly permanent manual block — never re-evaluate
                return state.action_taken

            if state is None:
                if confidence < MIN_QUARANTINE_CONFIDENCE and attack_class == "Uncertain":
                    return "Skipped"

                state = IpState(
                    src_ip        = src_ip,
                    phase         = 1,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    action_taken  = "Quarantined",
                )
                self._states[src_ip] = state
                self._push_command(src_ip, "quarantine")
                log.info("Phase 1 Quarantine: %s  (conf=%.1f%%  vector=%s)",
                         src_ip, confidence * 100, attack_class)
                self._persist(state)
            else:
                state.if_score      = if_score
                state.confidence    = confidence
                state.attack_vector = attack_class
                self._persist(state)

            return state.action_taken

    def tick(self) -> None:
        now = time.monotonic()
        with self._lock:
            for src_ip, state in list(self._states.items()):
                # Truly permanent manual blocks never auto-expire
                if state.permanent and state.ttl_expires_at is None:
                    continue

                elapsed = now - state.phase_entered

                if state.phase == 1 and elapsed >= PHASE1_DURATION:
                    self._advance(state, 2)
                elif state.phase == 2 and elapsed >= PHASE2_DURATION:
                    self._advance(state, 3)
                elif state.phase == 4 and elapsed >= PROBATION_DURATION:
                    self._clear(src_ip)
                # Feature 1 TTL expiry for auto-blocks
                elif (state.phase == 3
                      and state.ttl_expires_at is not None
                      and now >= state.ttl_expires_at):
                    log.info("TTL expired for %s — auto-unblocking", src_ip)
                    self._clear(src_ip)

    def _advance(self, state: IpState, new_phase: int) -> None:
        state.phase         = new_phase
        state.phase_entered = time.monotonic()

        if new_phase == 2:
            state.action_taken = "Rate Limited"
            self._push_command(state.src_ip, "rate_limit")
            log.info("Phase 2 Rate Limit: %s", state.src_ip)
            self._persist(state)

        elif new_phase == 3:
            state.action_taken   = "Blocked"
            state.permanent      = True   # survive DB restart
            state.ttl_expires_at = time.monotonic() + BLOCK_TTL_SECONDS
            # Compute wall-clock expiry for DB persistence (H5 fix)
            exp_dt  = datetime.datetime.now() + datetime.timedelta(seconds=BLOCK_TTL_SECONDS)
            exp_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S")
            self._push_command(state.src_ip, "block", ttl=BLOCK_TTL_SECONDS)
            log.info("Phase 3 Block: %s  (TTL=%ds, expires=%s)",
                     state.src_ip, BLOCK_TTL_SECONDS, exp_str)
            self._persist(state, block_expires_at=exp_str)

    def _clear(self, src_ip: str) -> None:
        self._states.pop(src_ip, None)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        log.info("Cleared: %s", src_ip)

    # ------------------------------------------------------------------
    # Manual operator actions
    # ------------------------------------------------------------------

    def manual_release(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip not in self._states:
                return False
            self._states.pop(src_ip)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        writer.log_manual_action(src_ip, "manual_release")
        log.info("Manual release: %s", src_ip)
        return True

    def clear_all_non_permanent(self) -> int:
        cleared = 0
        with self._lock:
            to_remove = [
                ip for ip, s in self._states.items()
                if not s.permanent or s.ttl_expires_at is not None
            ]
            for ip in to_remove:
                self._push_command(ip, "clear")
                writer.delete_quarantine_state(ip)
                del self._states[ip]
                cleared += 1
        if cleared:
            log.info("Cleared %d non-permanent/TTL quarantine entries", cleared)
        return cleared

    def manual_block(self, src_ip: str) -> bool:
        """Permanent manual block — no TTL, survives restarts indefinitely."""
        with self._lock:
            state = self._states.get(src_ip)
            if state is None:
                state = IpState(
                    src_ip         = src_ip,
                    phase          = 3,
                    action_taken   = "Blocked",
                    permanent      = True,
                    ttl_expires_at = None,
                )
                self._states[src_ip] = state
            else:
                state.phase          = 3
                state.phase_entered  = time.monotonic()
                state.action_taken   = "Blocked"
                state.permanent      = True
                state.ttl_expires_at = None   # upgrade to permanent — remove TTL
            # Persist with block_expires_at=None (permanent)
            self._persist(state, block_expires_at=None)
        # ttl=None → Ryu sets hard_timeout=0 (permanent OFP rule)
        self._push_command(src_ip, "block", ttl=None)
        writer.log_manual_action(src_ip, "manual_block")
        log.info("Manual block (permanent): %s", src_ip)
        return True

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def get_active_list(self) -> list[dict]:
        with self._lock:
            rows = [s.to_api_dict() for s in self._states.values()]
        rows.sort(key=lambda r: r["if_score"], reverse=True)
        return rows

    def is_active(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._states

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _persist(self, state: IpState,
                 block_expires_at: Optional[str] = None) -> None:
        writer.save_quarantine_state(
            src_ip           = state.src_ip,
            phase            = state.phase,
            attack_vector    = state.attack_vector,
            if_score         = state.if_score,
            confidence       = state.confidence,
            action_taken     = state.action_taken,
            permanent        = state.permanent,
            block_expires_at = block_expires_at,
        )

    def _push_command(self, src_ip: str, action: str,
                      ttl: Optional[int] = None) -> None:
        """Send ZMQ command to Ryu.

        ttl (seconds): passed to Ryu as hard_timeout for the OFP flow rule.
        ttl=None → hard_timeout=0 (permanent, for manual blocks).
        ttl=3600 → OFP rule self-expires at the switch after 1 hour.
        """
        if self._commander:
            cmd = {"action": action, "src_ip": src_ip}
            if ttl is not None:
                cmd["ttl"] = ttl
            self._commander.send(cmd)


# Module-level singleton
state_machine = StateMachine()


def start_tick_thread() -> None:
    def _loop():
        while True:
            time.sleep(1.0)
            state_machine.tick()

    t = threading.Thread(target=_loop, name="sm-tick", daemon=True)
    t.start()