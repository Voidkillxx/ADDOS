import time
import threading
from collections import OrderedDict
from backend.config import FLOW_TRACKER_CAP, INFERENCE_CACHE_TTL_S


class FlowEntry:
    __slots__ = ("flow_stats", "pkt_count", "first_seen", "last_seen")

    def __init__(self, flow_stats: dict):
        self.flow_stats  = flow_stats
        self.pkt_count   = int(flow_stats.get("packet_count", 0))
        self.first_seen  = time.monotonic()
        self.last_seen   = self.first_seen

    def update(self, flow_stats: dict) -> None:
        self.flow_stats = flow_stats
        self.pkt_count  = int(flow_stats.get("packet_count", 0))
        self.last_seen  = time.monotonic()


class InferenceCacheEntry:
    __slots__ = ("if_score", "is_anomaly", "attack_class", "confidence", "expires_at")

    def __init__(self, if_score: float, is_anomaly: bool,
                 attack_class: str, confidence: float):
        self.if_score     = if_score
        self.is_anomaly   = is_anomaly
        self.attack_class = attack_class
        self.confidence   = confidence
        self.expires_at   = time.monotonic() + INFERENCE_CACHE_TTL_S

    def is_valid(self) -> bool:
        return time.monotonic() < self.expires_at


class FlowTracker:
    """Tracks active flows per src_ip with a 500-entry cap.

    H6 fix: _cache is now protected by the same _lock as _flows.
    Previously cache operations had no lock — safe with a single worker
    thread but a latent race condition for any future second worker.
    """

    def __init__(self):
        self._lock   = threading.Lock()
        self._flows: OrderedDict[str, FlowEntry]    = OrderedDict()
        self._cache: dict[str, InferenceCacheEntry] = {}

    # ------------------------------------------------------------------
    # Flow tracking
    # ------------------------------------------------------------------

    def update_flow(self, src_ip: str, flow_stats: dict) -> FlowEntry:
        with self._lock:
            if src_ip in self._flows:
                self._flows[src_ip].update(flow_stats)
                self._flows.move_to_end(src_ip)
            else:
                if len(self._flows) >= FLOW_TRACKER_CAP:
                    self._flows.popitem(last=False)
                self._flows[src_ip] = FlowEntry(flow_stats)
            return self._flows[src_ip]

    def get_flow(self, src_ip: str) -> FlowEntry | None:
        with self._lock:
            return self._flows.get(src_ip)

    def remove_flow(self, src_ip: str) -> None:
        with self._lock:
            self._flows.pop(src_ip, None)

    def active_count(self) -> int:
        with self._lock:
            return len(self._flows)

    # ------------------------------------------------------------------
    # Inference cache — H6: all operations now lock-protected
    # ------------------------------------------------------------------

    def get_cached(self, src_ip: str) -> InferenceCacheEntry | None:
        with self._lock:
            entry = self._cache.get(src_ip)
            if entry and entry.is_valid():
                return entry
            self._cache.pop(src_ip, None)
            return None

    def set_cache(self, src_ip: str, if_score: float, is_anomaly: bool,
                  attack_class: str, confidence: float) -> None:
        with self._lock:
            self._cache[src_ip] = InferenceCacheEntry(
                if_score, is_anomaly, attack_class, confidence
            )

    def invalidate_cache(self, src_ip: str) -> None:
        with self._lock:
            self._cache.pop(src_ip, None)

    def purge_expired_cache(self) -> None:
        now = time.monotonic()
        with self._lock:
            expired = [ip for ip, e in self._cache.items() if now >= e.expires_at]
            for ip in expired:
                del self._cache[ip]


# Module-level singleton shared across pipeline components
tracker = FlowTracker()