import json
import threading
import joblib
import numpy as np
from backend.config import (
    IF_MODEL_PATH, IF_SCALER_PATH, IF_CONTRACT_PATH,
    RF_MODEL_PATH, RF_SCALER_PATH, RF_CONTRACT_PATH, RF_ENCODER_PATH,
)

_lock = threading.Lock()
_loaded = False

# Singletons — populated once at startup
if_model    = None
if_scaler   = None
rf_model    = None
rf_scaler   = None
rf_encoder  = None

if_features: list[str] = []
if_threshold: float    = 0.0

rf_features: list[str] = []
rf_classes:  list[str] = []
rf_conf_gate: float    = 0.55


def load_all() -> None:
    global _loaded
    global if_model, if_scaler, rf_model, rf_scaler, rf_encoder
    global if_features, if_threshold
    global rf_features, rf_classes, rf_conf_gate

    with _lock:
        if _loaded:
            return

        with open(IF_CONTRACT_PATH) as f:
            if_contract = json.load(f)
        if_features  = if_contract["feature_names"]
        if_threshold = float(if_contract["threshold"])   # sole source of truth

        with open(RF_CONTRACT_PATH) as f:
            rf_contract = json.load(f)
        rf_features  = rf_contract["feature_names"]
        rf_classes   = rf_contract["class_names"]
        rf_conf_gate = float(rf_contract["confidence_gate"])

        if_model   = joblib.load(IF_MODEL_PATH)
        if_scaler  = joblib.load(IF_SCALER_PATH)
        rf_model   = joblib.load(RF_MODEL_PATH)
        rf_scaler  = joblib.load(RF_SCALER_PATH)
        rf_encoder = joblib.load(RF_ENCODER_PATH)

        _loaded = True


def require_loaded() -> None:
    if not _loaded:
        raise RuntimeError("Models not loaded — call loader.load_all() at startup.")