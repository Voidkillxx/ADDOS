import time
import threading
from collections import defaultdict
from backend.config import SYN_HALFOPEN_LIMIT, SYN_WINDOW_S


class _SynWindow:
    __slots__ = ("syn_times",)

    def __init__(self):
        self.syn_times: list[float] = []

    def record_syn(self, now: float) -> None:
        self.syn_times.append(now)

    def ack_received(self) -> None:
        # Remove one SYN to account for the completed handshake
        if self.syn_times:
            self.syn_times.pop(0)

    def count_halfopen(self, now: float) -> int:
        cutoff = now - SYN_WINDOW_S
        self.syn_times = [t for t in self.syn_times if t >= cutoff]
        return len(self.syn_times)


class SynPreFilter:
    """Lightweight half-open TCP connection tracker.

    Fires a fast-quarantine flag when a src_ip exceeds SYN_HALFOPEN_LIMIT
    unacknowledged SYNs within a SYN_WINDOW_S sliding window.
    The full IF pipeline still runs regardless — this is a pre-filter only.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._windows: dict[str, _SynWindow] = defaultdict(_SynWindow)
        # IPs confirmed by pre-filter — cleared when state machine takes over
        self._flagged: set[str] = set()

    def on_syn(self, src_ip: str) -> bool:
        """Record a SYN packet. Returns True if fast-quarantine should trigger."""
        now = time.monotonic()
        with self._lock:
            win = self._windows[src_ip]
            win.record_syn(now)
            count = win.count_halfopen(now)
            if count >= SYN_HALFOPEN_LIMIT and src_ip not in self._flagged:
                self._flagged.add(src_ip)
                return True
        return False

    def on_ack(self, src_ip: str) -> None:
        with self._lock:
            if src_ip in self._windows:
                self._windows[src_ip].ack_received()

    def is_flagged(self, src_ip: str) -> bool:
        with self._lock:
            return src_ip in self._flagged

    def clear_flag(self, src_ip: str) -> None:
        with self._lock:
            self._flagged.discard(src_ip)
            self._windows.pop(src_ip, None)

    def purge_stale(self) -> None:
        """Remove windows with no recent SYNs to keep memory bounded."""
        now = time.monotonic()
        with self._lock:
            stale = [
                ip for ip, w in self._windows.items()
                if not w.syn_times or (now - w.syn_times[-1]) > SYN_WINDOW_S * 5
            ]
            for ip in stale:
                self._windows.pop(ip, None)


# Module-level singleton
syn_filter = SynPreFilter()