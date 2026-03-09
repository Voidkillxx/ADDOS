import numpy as np
from backend.models import loader


def extract_rf_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,20) feature matrix from Ryu per-switch aggregate fields."""
    loader.require_loaded()

    s = flow_stats

    # --- Raw switch-level inputs ---
    disp_pakt_raw    = float(s.get("disp_pakt",      0))
    disp_byte_raw    = float(s.get("disp_byte",      0))
    mean_pkt_raw     = float(s.get("mean_pkt",       0))
    mean_byte_raw    = float(s.get("mean_byte",      0))
    avg_durat_raw    = float(s.get("avg_durat",      0))   # µs from Ryu → multiply by 1000 → ns
    avg_flow_dst_raw = float(s.get("avg_flow_dst",   0))
    rate_pkt_in_raw  = float(s.get("rate_pkt_in",    0))
    disp_interval_raw= float(s.get("disp_interval",  1))   # avoid /0 below
    gfe_raw          = float(s.get("gfe",            0))
    g_usip_raw       = float(s.get("g_usip",         0))
    rfip_raw         = float(s.get("rfip",           0))
    gsp_raw          = float(s.get("gsp",            0))

    # --- [0]–[11]: base features ---
    # avg_durat arrives in µs from Ryu — multiply by 1000 to get ns
    avg_durat_ns = avg_durat_raw * 1000.0

    f = [
        np.log1p(max(disp_pakt_raw,    0)),   # [0]
        np.log1p(max(disp_byte_raw,    0)),   # [1]
        np.log1p(max(mean_pkt_raw,     0)),   # [2]
        np.log1p(max(mean_byte_raw,    0)),   # [3]
        avg_durat_ns,                          # [4] RAW — not log-transformed
        np.log1p(max(avg_flow_dst_raw, 0)),   # [5]
        np.log1p(max(rate_pkt_in_raw,  0)),   # [6]
        disp_interval_raw,                     # [7] RAW
        gfe_raw,                               # [8] RAW
        np.log1p(max(g_usip_raw,       0)),   # [9]
        np.log1p(max(rfip_raw,         0)),   # [10]
        gsp_raw,                               # [11] RAW
    ]

    # --- [12]–[14]: Group A — switch-adapted engineered features ---
    # Analogous to IF [11]–[13] but use switch-level fields (different semantics)

    # [12] flow_duration_total_ns — RAW value used here, not log-transformed
    fdt = np.log1p(max(avg_durat_ns, 0))

    # [13] bytes_per_packet — RAW ratio
    bpp = np.log1p(max(disp_byte_raw / (disp_pakt_raw + 1e-9), 0))

    # [14] pkt_byte_rate_ratio — RAW ratio
    pbr = np.log1p(max(
        (disp_pakt_raw / disp_interval_raw) /
        ((disp_byte_raw / disp_interval_raw) + 1e-9), 0
    ))

    f += [fdt, bpp, pbr]

    # --- [15]–[19]: Group B — SDN extra engineered features ---

    # [15] ip_diversity_ratio — unique src IPs vs remote IPs (rfip, matches training)
    ip_div = np.log1p(max(g_usip_raw / (rfip_raw + 1e-9), 0))

    # [16] byte_per_interval — total bytes passed during this polling interval
    bpi = np.log1p(max(disp_byte_raw / (disp_interval_raw + 1e-9), 0))

    # [17] pkt_per_interval — total packets passed during this polling interval
    ppi = np.log1p(max(disp_pakt_raw / (disp_interval_raw + 1e-9), 0))

    # [18] flow_entry_ratio — flow entries per active port
    fer = np.log1p(max(gfe_raw / (gsp_raw + 1e-9), 0))

    # [19] mean_pkt_byte_ratio — mean pkts per mean bytes
    mpbr = np.log1p(max(mean_pkt_raw / (mean_byte_raw + 1e-9), 0))

    f += [ip_div, bpi, ppi, fer, mpbr]

    # --- [20]–[22]: Protocol-proxy features (ip_proto substitute) ---
    # Packet size fingerprints: ICMP~84B | SYN~60B | UDP variable
    # Must use RAW values — not log-transformed (matches training preprocess)
    bpp_raw = disp_byte_raw / (disp_pakt_raw + 1e-9)
    bytes_per_packet_raw = max(bpp_raw, 0)                 # [20] raw B/pkt
    mean_byte_raw        = max(mean_byte_raw, 0)           # [21] raw mean_byte
    pkt_size_bucket      = round(bpp_raw / 20) * 20        # [22] nearest 20B bucket

    f += [bytes_per_packet_raw, mean_byte_raw, pkt_size_bucket]

    vec = np.array(f, dtype=np.float64)

    # Replace inf/-inf with 0 — RF is robust to missing switch stats
    vec = np.where(np.isfinite(vec), vec, 0.0)

    import pandas as pd
    # Scaler was fitted with feature names — pass DataFrame to silence warning
    df = pd.DataFrame(vec.reshape(1, -1), columns=loader.rf_features)
    vec_scaled = loader.rf_scaler.transform(df)
    return vec_scaled   # shape (1, 20)


def run_rf_inference(vec_scaled: np.ndarray) -> tuple[str, float]:
    """Return (attack_class_or_Uncertain, confidence).

    Decodes via label_encoder. Returns 'Uncertain' if conf < confidence_gate.
    """
    loader.require_loaded()

    proba   = loader.rf_model.predict_proba(vec_scaled)[0]
    idx     = int(np.argmax(proba))
    conf    = float(proba[idx])

    # confidence gate from contract, not hardcoded
    if conf >= loader.rf_conf_gate:
        attack_class = loader.rf_encoder.inverse_transform([idx])[0]
    else:
        attack_class = "Uncertain"

    return attack_class, conf