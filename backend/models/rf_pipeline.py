import numpy as np
from backend.models import loader


def extract_rf_features(flow_stats: dict) -> np.ndarray:
    """Build shape-(1,24) feature matrix from Ryu per-switch aggregate fields."""
    loader.require_loaded()

    s = flow_stats

    # --- Raw switch-level inputs ---
    disp_pakt_raw    = float(s.get("disp_pakt",      0))
    disp_byte_raw    = float(s.get("disp_byte",      0))
    mean_pkt_raw     = float(s.get("mean_pkt",       0))
    mean_byte_raw    = float(s.get("mean_byte",      0))
    avg_durat_raw    = float(s.get("avg_durat",      0))
    avg_flow_dst_raw = float(s.get("avg_flow_dst",   0))
    rate_pkt_in_raw  = float(s.get("rate_pkt_in",    0))
    disp_interval_raw= float(s.get("disp_interval",  1))   # avoid /0 below
    gfe_raw          = float(s.get("gfe",            0))
    g_usip_raw       = float(s.get("g_usip",         0))
    rfip_raw         = float(s.get("rfip",           0))
    gsp_raw          = float(s.get("gsp",            0))
    # ip_proto: ICMP=1, TCP=6, UDP=17 — injected from flow at inference time
    ip_proto_raw     = float(s.get("ip_proto",       0))

    # --- [0]–[11]: base features ---
    # avg_durat arrives in µs from Ryu — multiply by 1000 to get ns
    avg_durat_ns = avg_durat_raw * 1000.0

    f = [
        np.log1p(max(disp_pakt_raw,    0)),   # [0]  disp_pakt
        np.log1p(max(disp_byte_raw,    0)),   # [1]  disp_byte
        np.log1p(max(mean_pkt_raw,     0)),   # [2]  mean_pkt
        np.log1p(max(mean_byte_raw,    0)),   # [3]  mean_byte
        avg_durat_ns,                          # [4]  avg_durat  RAW ns
        np.log1p(max(avg_flow_dst_raw, 0)),   # [5]  avg_flow_dst
        np.log1p(max(rate_pkt_in_raw,  0)),   # [6]  rate_pkt_in
        disp_interval_raw,                     # [7]  disp_interval RAW
        gfe_raw,                               # [8]  gfe RAW
        np.log1p(max(g_usip_raw,       0)),   # [9]  g_usip
        np.log1p(max(rfip_raw,         0)),   # [10] rfip
        gsp_raw,                               # [11] gsp RAW
        ip_proto_raw,                          # [12] ip_proto (ICMP=1,TCP=6,UDP=17)
    ]

    # --- [13]–[15]: Group A — switch-adapted engineered features ---

    # [13] flow_duration_total_ns
    fdt = np.log1p(max(avg_durat_ns, 0))

    # [14] bytes_per_packet
    bpp = np.log1p(max(disp_byte_raw / (disp_pakt_raw + 1e-9), 0))

    # [15] pkt_byte_rate_ratio
    pbr = np.log1p(max(
        (disp_pakt_raw / disp_interval_raw) /
        ((disp_byte_raw / disp_interval_raw) + 1e-9), 0
    ))

    f += [fdt, bpp, pbr]

    # --- [16]–[20]: Group B — SDN extra engineered features ---

    # [16] ip_diversity_ratio
    ip_div = np.log1p(max(g_usip_raw / (rfip_raw + 1e-9), 0))

    # [17] byte_per_interval
    bpi = np.log1p(max(disp_byte_raw / (disp_interval_raw + 1e-9), 0))

    # [18] pkt_per_interval
    ppi = np.log1p(max(disp_pakt_raw / (disp_interval_raw + 1e-9), 0))

    # [19] flow_entry_ratio
    fer = np.log1p(max(gfe_raw / (gsp_raw + 1e-9), 0))

    # [20] mean_pkt_byte_ratio
    mpbr = np.log1p(max(mean_pkt_raw / (mean_byte_raw + 1e-9), 0))

    f += [ip_div, bpi, ppi, fer, mpbr]

    # --- [21]–[23]: Protocol-proxy features ---
    # Must use RAW values — not log-transformed (matches training preprocess)
    bpp_raw          = disp_byte_raw / (disp_pakt_raw + 1e-9)
    bytes_per_packet_raw = max(bpp_raw, 0)       # [21]
    mean_byte_raw_val    = max(mean_byte_raw, 0) # [22]
    pkt_size_bucket      = round(bpp_raw / 20) * 20  # [23] nearest 20B bucket

    f += [bytes_per_packet_raw, mean_byte_raw_val, pkt_size_bucket]

    vec = np.array(f, dtype=np.float64)

    # Replace inf/-inf with 0 — RF is robust to missing switch stats
    vec = np.where(np.isfinite(vec), vec, 0.0)

    import pandas as pd
    # Scaler was fitted with feature names — pass DataFrame to silence warning
    df = pd.DataFrame(vec.reshape(1, -1), columns=loader.rf_features)
    vec_scaled = loader.rf_scaler.transform(df)
    return vec_scaled   # shape (1, 24)


def run_rf_inference(vec_scaled: np.ndarray) -> tuple[str, float]:
    """Return (attack_class_or_Uncertain, confidence).

    Decodes via label_encoder. Returns 'Uncertain' if conf < confidence_gate.
    """
    loader.require_loaded()

    proba = loader.rf_model.predict_proba(vec_scaled)[0]
    idx   = int(np.argmax(proba))
    conf  = float(proba[idx])

    if conf >= loader.rf_conf_gate:
        attack_class = loader.rf_encoder.inverse_transform([idx])[0]
    else:
        attack_class = "Uncertain"

    return attack_class, conf