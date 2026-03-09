THEME_CONFIG = {
    "Dark":  {"bg": "#0f0f12", "card": "#1a1a21", "text": "#ffffff",
              "subtext": "#9ca3af", "border": "#2d2d3a"},
    "Light": {"bg": "#f9fafb", "card": "#ffffff",  "text": "#111827",
              "subtext": "#6b7280", "border": "#e5e7eb"},
}

# (Light, Dark) tuples
ACCENT_BLUE    = ("#2563eb", "#3b82f6")
DANGER_RED     = ("#dc2626", "#ef4444")
SUCCESS_GREEN  = ("#16a34a", "#10b981")
WARNING_ORANGE = ("#ea580c", "#f59e0b")

CLASS_COLORS = {
    "Anomaly": {"bg": ("#ffedd5", "#78350f"), "text": ("#9a3412",  "#fbbf24")},
    "DDoS":    {"bg": ("#fee2e2", "#7f1d1d"), "text": ("#991b1b",  "#f87171")},
}

ACTION_COLORS = {
    "Quarantined":  {"border": ("#fcd34d", "#b45309"), "text": ("#92400e", "#fbbf24")},
    "Rate Limited": {"border": ("#fb923c", "#c2410c"), "text": ("#c2410c", "#fb923c")},
    "Blocked":      {"border": ("#fca5a5", "#dc2626"), "text": ("#b91c1c", "#f87171")},
}

# class_names come from rf_sdn_feature_contract.json — must match exactly
VECTOR_COLORS = {
    "SYN Flood":  {"bg": ("#ffedd5", "#78350f"), "text": ("#9a3412", "#fbbf24")},
    "UDP Flood":  {"bg": ("#e0f2fe", "#0c4a6e"), "text": ("#0369a1", "#38bdf8")},
    "ICMP Flood": {"bg": ("#fce7f3", "#831843"), "text": ("#be185d", "#f472b6")},
    "Uncertain":  {"bg": ("#f3f4f6", "#374151"), "text": ("#6b7280", "#9ca3af")},
}

PRIORITY_COLORS = {
    "Low":  {"text": ("#6b7280", "#9ca3af")},
    "High": {"text": ("#dc2626", "#ef4444")},
}

# IF score colour thresholds for quarantine panel (applied dynamically)
IF_SCORE_RED   = 1.2   # multiplier of threshold → clearly anomalous
IF_SCORE_AMBER = 1.0   # at threshold → borderline
# below threshold → green (possible false positive)