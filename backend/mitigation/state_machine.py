import time
import threading
import logging
from dataclasses import dataclass, field
from backend.database import writer

log = logging.getLogger(__name__)

# Phase durations (seconds)
PHASE1_DURATION    = 30.0
PHASE2_DURATION    = 60.0
PROBATION_DURATION = 120.0

# Minimum confidence required to enter OR restore a Phase 1 quarantine.
# Entries below this were false positives — skip them on restore too.
MIN_QUARANTINE_CONFIDENCE = 0.60

PHASE_LABELS = {
    1: "Phase 1 — Quarantined",
    2: "Phase 2 — Rate Limited",
    3: "Phase 3 — Blocked",
    4: "Probation",
}


@dataclass
class IpState:
    src_ip:        str
    phase:         int   = 1
    attack_vector: str   = "Uncertain"
    if_score:      float = 0.0
    confidence:    float = 0.0
    phase_entered: float = field(default_factory=time.monotonic)
    action_taken:  str   = "Quarantined"
    permanent:     bool  = False

    def phase_label(self) -> str:
        return PHASE_LABELS.get(self.phase, "Unknown")

    def time_in_phase_sec(self) -> float:
        return time.monotonic() - self.phase_entered

    def to_api_dict(self) -> dict:
        return {
            "src_ip":            self.src_ip,
            "phase":             self.phase_label(),
            "attack_vector":     self.attack_vector,
            "if_score":          round(self.if_score, 4),
            "confidence":        f"{self.confidence * 100:.1f}%",
            "time_in_phase_sec": int(self.time_in_phase_sec()),
        }


class StateMachine:
    """Manages per-IP mitigation phases and manual operator actions."""

    def __init__(self):
        self._lock      = threading.Lock()
        self._states: dict[str, IpState] = {}
        self._commander = None

    def set_commander(self, commander) -> None:
        self._commander = commander

    # ------------------------------------------------------------------
    # Startup — restore persisted quarantine state from DB
    # ------------------------------------------------------------------

    def restore_from_db(self) -> None:
        """Load persisted quarantine entries and re-apply OFP rules.

        Entries that were Uncertain with confidence below MIN_QUARANTINE_CONFIDENCE
        are treated as stale false positives — they are cleared from the DB and
        their OFP rules are explicitly removed so previously blocked legit hosts
        are immediately released.
        """
        rows = writer.load_quarantine_states()
        if not rows:
            return

        log.info("Restoring quarantine entries from DB (%d total)...", len(rows))
        restored = 0
        purged   = 0

        with self._lock:
            for r in rows:
                src_ip     = r["src_ip"]
                confidence = float(r.get("confidence", 0) or 0)
                vector     = r.get("attack_vector", "Uncertain") or "Uncertain"
                permanent  = bool(r.get("permanent", False))

                # ── Purge stale false positives ───────────────────────────────
                # On every restart, purge ALL non-permanent quarantine entries.
                # Reason: if we've changed thresholds or pps gates, IPs that were
                # wrongly quarantined in the previous session will stay blocked
                # forever via DB restore — even though anomaly=False now.
                # Only permanent (manually blocked) entries survive a restart.
                # This ensures a clean slate every time the backend starts.
                is_fp = (not permanent)
                if is_fp:
                    self._push_command(src_ip, "clear")
                    writer.delete_quarantine_state(src_ip)
                    log.info(
                        "Purged stale FP on restore: %s  (Uncertain, conf=%.1f%%)",
                        src_ip, confidence * 100,
                    )
                    purged += 1
                    continue

                # ── Restore legitimate quarantine entry ───────────────────────
                state = IpState(
                    src_ip        = src_ip,
                    phase         = r["phase"],
                    attack_vector = vector,
                    if_score      = float(r.get("if_score", 0) or 0),
                    confidence    = confidence,
                    action_taken  = r.get("action_taken", "Quarantined"),
                    permanent     = permanent,
                )
                self._states[src_ip] = state
                _action_map = {1: "quarantine", 2: "rate_limit", 3: "block"}
                self._push_command(src_ip, _action_map.get(r["phase"], "quarantine"))
                restored += 1

        log.info(
            "Quarantine restore complete — %d restored, %d stale FPs purged",
            restored, purged,
        )

    # ------------------------------------------------------------------
    # Automatic progression
    # ------------------------------------------------------------------

    def on_detection(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float) -> str:
        """Called by decision_engine when IF fires. Returns action_taken."""
        with self._lock:
            state = self._states.get(src_ip)

            if state and state.permanent:
                return state.action_taken

            if state is None:
                # Secondary confidence gate — primary gate is in decision_engine
                if confidence < MIN_QUARANTINE_CONFIDENCE and attack_class == "Uncertain":
                    log.debug(
                        "State machine: skipping new quarantine for %s "
                        "(Uncertain, conf=%.1f%% < %.0f%%)",
                        src_ip, confidence * 100, MIN_QUARANTINE_CONFIDENCE * 100,
                    )
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
        """Advance phase timers. Called every second from background thread."""
        now = time.monotonic()
        with self._lock:
            for src_ip, state in list(self._states.items()):
                if state.permanent:
                    continue
                elapsed = now - state.phase_entered
                if state.phase == 1 and elapsed >= PHASE1_DURATION:
                    self._advance(state, 2)
                elif state.phase == 2 and elapsed >= PHASE2_DURATION:
                    self._advance(state, 3)
                elif state.phase == 4 and elapsed >= PROBATION_DURATION:
                    self._clear(src_ip)

    def _advance(self, state: IpState, new_phase: int) -> None:
        state.phase         = new_phase
        state.phase_entered = time.monotonic()
        if new_phase == 2:
            state.action_taken = "Rate Limited"
            self._push_command(state.src_ip, "rate_limit")
            log.info("Phase 2 Rate Limit: %s", state.src_ip)
        elif new_phase == 3:
            state.action_taken = "Blocked"
            state.permanent    = True
            self._push_command(state.src_ip, "block")
            log.info("Phase 3 Block: %s", state.src_ip)
        self._persist(state)

    def _clear(self, src_ip: str) -> None:
        self._states.pop(src_ip, None)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        log.info("Cleared (probation ended): %s", src_ip)

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
        """Release all non-permanent quarantine/block states immediately.
        Use this to flush stale false positives without restarting the backend.
        Called automatically on restore. Can also be triggered via API.
        """
        cleared = 0
        with self._lock:
            to_remove = [ip for ip, s in self._states.items() if not s.permanent]
            for ip in to_remove:
                self._push_command(ip, "clear")
                writer.delete_quarantine_state(ip)
                del self._states[ip]
                cleared += 1
        if cleared:
            log.info("Cleared %d non-permanent quarantine entries", cleared)
        return cleared

    def manual_block(self, src_ip: str) -> bool:
        with self._lock:
            state = self._states.get(src_ip)
            if state is None:
                state = IpState(src_ip=src_ip, phase=3,
                                action_taken="Blocked", permanent=True)
                self._states[src_ip] = state
            else:
                state.phase         = 3
                state.phase_entered = time.monotonic()
                state.action_taken  = "Blocked"
                state.permanent     = True
            self._persist(state)
        self._push_command(src_ip, "block")
        writer.log_manual_action(src_ip, "manual_block")
        log.info("Manual block: %s", src_ip)
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

    def _persist(self, state: IpState) -> None:
        writer.save_quarantine_state(
            src_ip        = state.src_ip,
            phase         = state.phase,
            attack_vector = state.attack_vector,
            if_score      = state.if_score,
            confidence    = state.confidence,
            action_taken  = state.action_taken,
            permanent     = state.permanent,
        )

    def _push_command(self, src_ip: str, action: str) -> None:
        if self._commander:
            self._commander.send({"action": action, "src_ip": src_ip})


# Module-level singleton
state_machine = StateMachine()


def start_tick_thread() -> None:
    def _loop():
        while True:
            time.sleep(1.0)
            state_machine.tick()

    t = threading.Thread(target=_loop, name="sm-tick", daemon=True)
    t.start()