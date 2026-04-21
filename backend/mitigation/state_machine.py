import time
import datetime
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional
from backend.database import writer
from backend.config import SIMULATION_MODE

log = logging.getLogger(__name__)

# ── Phase durations ────────────────────────────────────────────────────────────
# Phase 1 — Quarantine + Rate Limit:
#   15s for Low severity, 30s for High severity — faster response
PHASE1_DURATION_LOW  = 3.0   # Lowered from 10s for faster demo detection
PHASE1_DURATION_HIGH = 5.0   # Lowered from 15s for faster demo detection

# Phase 2 — Time Ban: escalating bans
# BUG 2 FIX: use short durations in SIMULATION_MODE so testers see full
# attack-detect-ban-release cycles without waiting 30 minutes.
if SIMULATION_MODE:
    BAN_LEVELS = [30, 60, 120, 300]   # seconds — short for simulation/demo
    log.warning("SIMULATION_MODE is ON — using short ban durations for testing: %s", BAN_LEVELS)
else:
    BAN_LEVELS = [120, 300, 600, 1800]  # seconds — production (2min→5min→10min→30min)
MAX_BAN_LEVEL  = len(BAN_LEVELS) - 1

# Phase 3 — Blackhole: full drop, 1hr TTL then auto-release
BLACKHOLE_TTL_SECONDS = 3600

PROBATION_DURATION = 120.0

MIN_QUARANTINE_CONFIDENCE = 0.60
CONFIDENCE_LOCK_THRESHOLD = 0.70   # attack_vector locked once confidence >= this

PHASE_LABELS = {
    1: "Phase 1 — Quarantined",
    2: "Phase 2 — Time Ban",
    3: "Phase 3 — Blackhole",
    4: "Probation",
}


@dataclass
class IpState:
    src_ip:         str
    phase:          int   = 1
    attack_vector:  str   = "Uncertain"
    if_score:       float = 0.0
    confidence:     float = 0.0
    priority:       str   = "Low"
    phase_entered:  float = field(default_factory=time.monotonic)
    action_taken:   str   = "Quarantined"
    permanent:      bool  = False
    ttl_expires_at: Optional[float] = None
    first_seen:     str   = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    # Escalation level for Phase 2 time bans (0-3)
    ban_level:      int   = 0
    # Track how many times IP has been through phase 1 (for escalation)
    offence_count:  int   = 0
    # F4 fix: most recent packets-per-second observed for this IP.
    # Updated on every result callback so _evaluate_phase1 can check
    # whether traffic is still active before escalating to time ban.
    recent_pps:     float = 0.0

    def phase_label(self) -> str:
        return PHASE_LABELS.get(self.phase, "Unknown")

    def time_in_phase_sec(self) -> float:
        return time.monotonic() - self.phase_entered

    def phase1_duration(self) -> float:
        """10s Low, 15s High, 30s Uncertain."""
        if self.attack_vector == "Uncertain":
            return 30.0
        return PHASE1_DURATION_HIGH if self.priority == "High" else PHASE1_DURATION_LOW

    def to_api_dict(self) -> dict:
        d = {
            "src_ip":            self.src_ip,
            "phase":             self.phase_label(),
            "attack_vector":     self.attack_vector,
            "if_score":          round(self.if_score, 4),
            "confidence":        f"{self.confidence * 100:.1f}%",
            "time_in_phase_sec": int(self.time_in_phase_sec()),
            "priority":          self.priority,
            "offence_count":     self.offence_count,
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
        rows = writer.load_quarantine_states()
        if not rows:
            return

        log.info("Restoring quarantine entries from DB (%d total)...", len(rows))
        restored = purged = expired = 0
        now_wall = datetime.datetime.now()

        with self._lock:
            for r in rows:
                src_ip           = r["src_ip"]
                permanent        = bool(r.get("permanent", False))
                block_expires_at = r.get("block_expires_at")

                if not permanent:
                    self._push_command(src_ip, "clear")
                    writer.delete_quarantine_state(src_ip)
                    log.info("Purged stale entry on restore: %s", src_ip)
                    purged += 1
                    continue

                if block_expires_at is not None:
                    try:
                        exp_dt      = datetime.datetime.strptime(block_expires_at, "%Y-%m-%d %H:%M:%S")
                        remaining_s = (exp_dt - now_wall).total_seconds()
                    except ValueError:
                        remaining_s = 0

                    if remaining_s <= 0:
                        self._push_command(src_ip, "clear")
                        writer.delete_quarantine_state(src_ip)
                        log.info("TTL expired during downtime, released: %s", src_ip)
                        expired += 1
                        continue

                    ttl_expires_at = time.monotonic() + remaining_s
                    ttl_for_cmd    = int(remaining_s)
                else:
                    ttl_expires_at = None
                    ttl_for_cmd    = None

                state = IpState(
                    src_ip         = src_ip,
                    phase          = r["phase"],
                    attack_vector  = r.get("attack_vector", "Uncertain"),
                    if_score       = float(r.get("if_score", 0) or 0),
                    confidence     = float(r.get("confidence", 0) or 0),
                    action_taken   = r.get("action_taken", "Quarantined"),
                    permanent      = permanent,
                    ttl_expires_at = ttl_expires_at,
                )
                self._states[src_ip] = state
                _action_map = {1: "rate_limit", 2: "rate_limit", 3: "block"}
                self._push_command(src_ip, _action_map.get(r["phase"], "rate_limit"), ttl=ttl_for_cmd)
                restored += 1

        log.info("Quarantine restore — %d restored, %d purged, %d TTL-expired", restored, purged, expired)

    # ------------------------------------------------------------------
    # Detection entry point
    # ------------------------------------------------------------------

    def on_detection(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float) -> str:
        with self._lock:
            state = self._states.get(src_ip)

            # Permanent manual blackhole — never re-evaluate
            if state and state.permanent and state.ttl_expires_at is None:
                return state.action_taken

            if state is None:
                # Never skip — IF score > threshold means anomaly confirmed.
                # Uncertain just means RF couldn't classify the attack type.
                # Quarantine and observe for 1 minute regardless.
                from backend.pipeline.decision_engine import _assign_priority as _ap
                _prio = _ap(if_score, confidence)

                # Phase 1: Quarantine + Rate Limit simultaneously
                # Rate limit immediately so attacker can't flood during observation
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 1,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    action_taken  = "Quarantined",
                    priority      = _prio,
                    offence_count = 1,
                )
                self._states[src_ip] = state
                # Apply BOTH quarantine (priority 90) AND rate_limit (priority 80)
                # simultaneously on Phase 1 entry.
                # SLIP-THROUGH FIX: previously only rate_limit (priority 80) was sent.
                # Priority 80 is the weakest drop rule — most attacker packets still
                # slipped through. Quarantine (priority 90) is stronger and drops
                # more aggressively. Sending both ensures maximum coverage across
                # all switches from the moment of first detection.
                self._push_command(src_ip, "quarantine")
                self._push_command(src_ip, "rate_limit")
                log.info("Phase 1 Quarantine+RateLimit: %s  (conf=%.1f%%  vector=%s  priority=%s  duration=%.0fs)",
                         src_ip, confidence * 100, attack_class, _prio, state.phase1_duration())
                self._persist(state)
            else:
                # Already tracked — update scores.
                # Lock attack_vector if:
                #   - IP is already in Phase 2/3 (Time Ban / Blackhole) — never
                #     let a new RF result flip the vector on a mid-ban IP.
                #   - OR previously classified with high confidence (>=70%, real class).
                # Prevents mixed-campaign switch stats from overwriting a confirmed type.
                _vector_locked = (
                    state.phase >= 2
                    or (
                        state.attack_vector != "Uncertain"
                        and state.confidence >= CONFIDENCE_LOCK_THRESHOLD
                    )
                )
                state.if_score   = if_score
                state.confidence = confidence
                if not _vector_locked:
                    state.attack_vector = attack_class
                self._persist(state)

            return state.action_taken

    # ------------------------------------------------------------------
    # Tick — automatic phase progression
    # ------------------------------------------------------------------

    def tick(self) -> None:
        now = time.monotonic()
        with self._lock:
            for src_ip, state in list(self._states.items()):
                # Permanent manual blackhole never auto-expires
                if state.permanent and state.ttl_expires_at is None:
                    continue

                elapsed = now - state.phase_entered

                if state.phase == 1 and elapsed >= state.phase1_duration():
                    # Phase 1 complete — check if attack persisted
                    # If IF score is still elevated → escalate to time ban
                    # If score dropped → release (attacker gave up)
                    self._evaluate_phase1(src_ip, state)

                elif state.phase == 2:
                    # Time ban — wait for TTL
                    if state.ttl_expires_at and now >= state.ttl_expires_at:
                        log.info("Time ban expired for %s (level %d) — releasing to probation",
                                 src_ip, state.ban_level)
                        self._clear(src_ip, reason="Ban Expired")

                elif state.phase == 3:
                    # Blackhole TTL
                    if state.ttl_expires_at and now >= state.ttl_expires_at:
                        log.info("Blackhole TTL expired for %s — auto-releasing", src_ip)
                        self._clear(src_ip, reason="Blackhole TTL Expired")

                elif state.phase == 4 and elapsed >= PROBATION_DURATION:
                    self._clear(src_ip, reason="Probation Complete")

    def _evaluate_phase1(self, src_ip: str, state: IpState) -> None:
        """After phase1 observation window: escalate to time ban or release.

        F4 fix: previously only checked IF score, which stays elevated in cache
        even after an attacker stops — the score is frozen at the last inference.
        Now also checks recent_pps (injected by worker on each result callback)
        so an IP that genuinely stopped attacking gets released instead of
        being escalated to a time ban based on a stale cached score.

        Decision logic:
          - IF score still >= threshold AND recent pps still elevated → escalate
          - IF score dropped OR recent pps near-zero → release (attack stopped)
        """
        from backend.models import loader
        thr = loader.if_threshold if loader._loaded else 0.6004

        # recent_pps is set by on_detection/on_result — zero if no recent flow data
        recent_pps = getattr(state, "recent_pps", None)

        score_elevated = state.if_score >= thr
        # pps threshold lowered 5.0→1.0 to match new flood gate in worker/ryu.
        # Previously attackers at 2-4 pps were released instead of escalated.
        pps_elevated   = (recent_pps is None) or (recent_pps > 1.0)

        if score_elevated and pps_elevated:
            # Both signals agree: attack persisted — escalate
            self._advance_to_ban(state)
        else:
            reason = (
                f"score normalized (IF={state.if_score:.4f} < thr={thr:.4f})"
                if not score_elevated
                else f"traffic stopped (pps={recent_pps:.1f} <= 1.0)"
            )
            log.info("Phase1 complete: %s %s — releasing", src_ip, reason)
            self._clear(src_ip, reason="Attack Stopped")

    def _advance_to_ban(self, state: IpState) -> None:
        """Escalate to Phase 2 time ban with escalating duration."""
        # Clear SSE dedup for this IP so the phase-change event is never
        # silently dropped by the 30s dedup window in decision_engine.
        try:
            from backend.pipeline.decision_engine import _sse_dedup, _sse_lock
            with _sse_lock:
                _sse_dedup.pop(state.src_ip, None)
        except Exception:
            pass
        # Bug fix: increment ban_level BEFORE lookup so each ban is longer
        # than the last. Previously ban_level was never incremented here,
        # so every ban always used the same level → always same duration.
        state.ban_level = min(state.ban_level + 1, MAX_BAN_LEVEL)
        ban_secs = BAN_LEVELS[state.ban_level]
        state.phase          = 2
        state.phase_entered  = time.monotonic()
        state.action_taken   = "Time Ban"
        state.permanent      = True
        state.ttl_expires_at = time.monotonic() + ban_secs

        exp_dt  = datetime.datetime.now() + datetime.timedelta(seconds=ban_secs)
        exp_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Full block during time ban
        self._push_command(state.src_ip, "block", ttl=ban_secs)
        log.info("Phase 2 Time Ban: %s  level=%d  duration=%ds  expires=%s",
                 state.src_ip, state.ban_level, ban_secs, exp_str)
        self._persist(state, block_expires_at=exp_str)

    def _advance_to_blackhole(self, state: IpState) -> None:
        """Escalate to Phase 3 Blackhole — max severity, 1hr TTL."""
        # Clear SSE dedup so the blackhole event always reaches the audit log.
        try:
            from backend.pipeline.decision_engine import _sse_dedup, _sse_lock
            with _sse_lock:
                _sse_dedup.pop(state.src_ip, None)
        except Exception:
            pass
        state.phase          = 3
        state.phase_entered  = time.monotonic()
        state.action_taken   = "Blackhole"
        state.permanent      = True
        state.ttl_expires_at = time.monotonic() + BLACKHOLE_TTL_SECONDS

        exp_dt  = datetime.datetime.now() + datetime.timedelta(seconds=BLACKHOLE_TTL_SECONDS)
        exp_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S")

        self._push_command(state.src_ip, "block", ttl=BLACKHOLE_TTL_SECONDS)
        log.info("Phase 3 Blackhole: %s  TTL=%ds  expires=%s",
                 state.src_ip, BLACKHOLE_TTL_SECONDS, exp_str)
        self._persist(state, block_expires_at=exp_str)

    def _clear(self, src_ip: str, reason: str = "Released") -> None:
        state = self._states.pop(src_ip, None)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        if state is not None:
            writer.log_attack_history(
                src_ip         = src_ip,
                attack_vector  = state.attack_vector,
                if_score       = state.if_score,
                confidence     = state.confidence,
                priority       = state.priority,
                phase_reached  = state.phase,
                first_seen     = state.first_seen,
                unblock_reason = reason,
            )
        log.info("Cleared: %s  reason=%s", src_ip, reason)

    # ------------------------------------------------------------------
    # Re-offence: IP re-detected after ban expired
    # ------------------------------------------------------------------

    def on_reoffence(self, src_ip: str, if_score: float,
                     attack_class: str, confidence: float,
                     prev_ban_level: int, prev_offence_count: int) -> None:
        """Called when a previously banned IP is detected again.

        Escalates ban level. If already at max ban level → blackhole.
        """
        with self._lock:
            from backend.pipeline.decision_engine import _assign_priority as _ap
            _prio       = _ap(if_score, confidence)
            new_ban_lvl = prev_ban_level + 1

            if new_ban_lvl > MAX_BAN_LEVEL:
                # Already at max ban → blackhole
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 3,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    priority      = _prio,
                    action_taken  = "Blackhole",
                    ban_level     = new_ban_lvl,
                    offence_count = prev_offence_count + 1,
                )
                self._states[src_ip] = state
                self._advance_to_blackhole(state)
                log.info("Re-offence → Blackhole: %s  offences=%d", src_ip, state.offence_count)
            else:
                # Escalate to next ban level via phase 1 observation first
                state = IpState(
                    src_ip        = src_ip,
                    phase         = 1,
                    attack_vector = attack_class,
                    if_score      = if_score,
                    confidence    = confidence,
                    priority      = _prio,
                    action_taken  = "Quarantined",
                    ban_level     = new_ban_lvl,
                    offence_count = prev_offence_count + 1,
                )
                self._states[src_ip] = state
                self._push_command(src_ip, "rate_limit")
                log.info("Re-offence → Phase1 (ban_level=%d next): %s  offences=%d",
                         new_ban_lvl, src_ip, state.offence_count)
                self._persist(state)

    # ------------------------------------------------------------------
    # Manual operator actions
    # ------------------------------------------------------------------

    def manual_release(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip not in self._states:
                return False
            state = self._states.pop(src_ip)
        self._push_command(src_ip, "clear")
        writer.delete_quarantine_state(src_ip)
        writer.log_manual_action(src_ip, "manual_release")
        writer.log_attack_history(
            src_ip         = src_ip,
            attack_vector  = state.attack_vector,
            if_score       = state.if_score,
            confidence     = state.confidence,
            priority       = state.priority,
            phase_reached  = state.phase,
            first_seen     = state.first_seen,
            unblock_reason = "Manual Release",
        )
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
            log.info("Cleared %d non-permanent/TTL entries", cleared)
        return cleared

    def manual_block(self, src_ip: str) -> bool:
        """Permanent manual blackhole — no TTL."""
        with self._lock:
            state = self._states.get(src_ip)
            if state is None:
                state = IpState(
                    src_ip         = src_ip,
                    phase          = 3,
                    action_taken   = "Blackhole",
                    permanent      = True,
                    ttl_expires_at = None,
                )
                self._states[src_ip] = state
            else:
                state.phase          = 3
                state.phase_entered  = time.monotonic()
                state.action_taken   = "Blackhole"
                state.permanent      = True
                state.ttl_expires_at = None
            self._persist(state, block_expires_at=None)
        self._push_command(src_ip, "block", ttl=None)
        writer.log_manual_action(src_ip, "manual_block")
        log.info("Manual blackhole (permanent): %s", src_ip)
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