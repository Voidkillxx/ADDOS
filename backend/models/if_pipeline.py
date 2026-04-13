import numpy as np
import threading
from backend.models import loader

# Per-feature running median tracker for NaN fill
_median_lock     = threading.Lock()
_feature_sums    = None
_feature_counts  = None
_feature_medians = None


def _init_median_tracker(n: int) -> None:
    global _feature_sums, _feature_counts, _feature_medians
    _feature_sums    = np.zeros(n, dtype=np.float64)
    _feature_counts  = np.zeros(n, dtype=np.int64)
    _feature_medians = np.zeros(n, dtype=np.float64)


def _update_medians(vec: np.ndarray) -> None:
    # Incremental mean used as a stable median approximation
    with _median_lock:
        mask = np.isfinite(vec)
        _feature_counts[mask] += 1
        _feature_sums[mask]   += vec[mask]
        np.divide(_feature_sums, np.maximum(_feature_counts, 1),
                  out=_feature_medians)


def _get_medians() -> np.ndarray:
    with _median_lock:
        return _feature_medians.copy()


def extract_if_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,14) feature matrix from raw Ryu OFPFlowStatsRequest fields."""
    loader.require_loaded()

    n = len(loader.if_features)
    if _feature_sums is None:
        _init_median_tracker(n)

    s = flow_stats

    # --- Raw fields ---
    fds  = float(s.get("flow_duration_sec",  0))
    fdns = float(s.get("flow_duration_nsec", 0))
    ito  = float(s.get("idle_timeout",       0))
    hto  = float(s.get("hard_timeout",       0))
    flg  = float(s.get("flags",              0))

    pkt_raw = float(s.get("packet_count", 0))
    byt_raw = float(s.get("byte_count",   0))

    # Recompute rates using exact same formula as sdn_collector_controller
    _total_s = fds + fdns / 1e9
    _total_s = max(_total_s, 1e-9)
    pps_raw  = pkt_raw / _total_s        # packet_count_per_second
    bps_raw  = byt_raw / _total_s        # byte_count_per_second
    ppns_raw = pps_raw / 1e9             # packet_count_per_nsecond
    bpns_raw = bps_raw / 1e9             # byte_count_per_nsecond

    # log1p-transformed (matches training preprocess step)
    pkt_log  = np.log1p(max(pkt_raw,  0))
    byt_log  = np.log1p(max(byt_raw,  0))
    pps_log  = np.log1p(max(pps_raw,  0))
    ppns_log = np.log1p(max(ppns_raw, 0))
    bps_log  = np.log1p(max(bps_raw,  0))
    bpns_log = np.log1p(max(bpns_raw, 0))

    # Engineered features
    # flow_duration_total_ns
    fdt_raw = fds * 1e9 + fdns
    fdt     = np.log1p(max(fdt_raw, 0))

    # bytes_per_packet
    bpp = np.log1p(max(byt_raw / (pkt_raw + 1e-9), 0))

    # pkt_byte_rate_ratio
    pbr = np.log1p(max(pps_raw / (bps_raw + 1e-9), 0))

    # 14 features matching scaler fitted feature order exactly:
    # flow_duration_sec, flow_duration_nsec, idle_timeout, hard_timeout, flags,
    # packet_count, byte_count, packet_count_per_second, packet_count_per_nsecond,
    # byte_count_per_second, byte_count_per_nsecond,
    # flow_duration_total_ns, bytes_per_packet, pkt_byte_rate_ratio
    vec = np.array([
        fds, fdns, ito, hto, flg,
        pkt_log, byt_log, pps_log, ppns_log, bps_log, bpns_log,
        fdt, bpp, pbr,
    ], dtype=np.float64)

    # Replace inf/-inf with NaN then fill with running median
    vec = np.where(np.isfinite(vec), vec, np.nan)
    _update_medians(vec)
    nans = np.isnan(vec)
    if nans.any():
        vec[nans] = _get_medians()[nans]

    import pandas as pd
    # Scaler was fitted with feature names — pass DataFrame to silence warning
    df = pd.DataFrame(vec.reshape(1, -1), columns=loader.if_features)
    vec_scaled = loader.if_scaler.transform(df)
    return vec_scaled   # shape (1, 14)


def run_if_inference(vec_scaled: np.ndarray) -> tuple[float, bool]:
    """Return (if_score, is_anomaly). Score uses negated sign per contract."""
    loader.require_loaded()
    if_score   = float(-loader.if_model.score_samples(vec_scaled)[0])
    is_anomaly = if_score >= loader.if_threshold
    return if_score, is_anomaly