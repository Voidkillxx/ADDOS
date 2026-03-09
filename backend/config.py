import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- Model asset paths ---
IF_DIR  = os.path.join(_ROOT, "models", "isolation_forest")
RF_DIR  = os.path.join(_ROOT, "models", "random_forest")

IF_MODEL_PATH    = os.path.join(IF_DIR, "isolation_forest.pkl")
IF_SCALER_PATH   = os.path.join(IF_DIR, "scaler.pkl")
IF_CONTRACT_PATH = os.path.join(IF_DIR, "feature_contract.json")

RF_MODEL_PATH    = os.path.join(RF_DIR, "random_forest_sdn_final.pkl")
RF_SCALER_PATH   = os.path.join(RF_DIR, "scaler.pkl")
RF_CONTRACT_PATH = os.path.join(RF_DIR, "rf_sdn_feature_contract.json")
RF_ENCODER_PATH  = os.path.join(RF_DIR, "label_encoder.pkl")

# --- Database ---
DB_PATH = os.path.join(_ROOT, "logs", "ddos.db")

# --- ZeroMQ ---
ZMQ_TELEMETRY_ADDR = "tcp://127.0.0.1:5555"   # Ryu PUSH → Backend PULL
ZMQ_COMMAND_ADDR   = "tcp://127.0.0.1:5556"   # Backend PUSH → Ryu PULL

# --- Pipeline tuning ---
FLOW_TRACKER_CAP       = 500
INFERENCE_CACHE_TTL_S  = 1.5    # reduced — stale anomaly cache causes FP on legit hosts
WORKER_QUEUE_MAXSIZE   = 1000
WORKER_ITEM_TIMEOUT_S  = 3.0   # was 1.5 — more time before fallback block fires
EXTRACTION_TRIGGER_PKTS = 10   # min pkts before IF inference fires
                                # (low enough for rand-source attacks, high enough to
                                #  block single-packet warmup/pingall false positives)
EXTRACTION_TRIGGER_S    = 2.0   # was 0.5 — wait longer before triggering on short flows

# --- SYN pre-filter ---
SYN_HALFOPEN_LIMIT  = 100
SYN_WINDOW_S        = 2.0

# --- API ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# --- Anomaly detection tuning ---
# Override the model's built-in threshold (0.598) with a slightly higher value
# to reduce false positives from bursty-but-legitimate traffic like pingall.
# Set to None to use the model's own threshold from feature_contract.json.
IF_SCORE_THRESHOLD_OVERRIDE = 0.72   # Raised from model default (0.620)
# Model default is too aggressive for Mininet — legit hosts score 0.62-0.71,
# real floods score 0.85-0.99. 0.72 creates a clean gap with near-zero FP.
# Set back to None to use the model's own threshold.

# Minimum packet count — zero-packet flows are always dropped.
# Real rate filtering is in ryu_controller.py via per-poll delta guard.
MIN_FLOW_PKTS_FOR_INFERENCE = 0

# --- UI batching ---
UI_BATCH_INTERVAL_S = 0.5

# --- Graph history ---
GRAPH_BUCKET_COUNT = 60