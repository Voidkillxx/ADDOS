# styles.py
# Theme Configurations
THEME_CONFIG = {
    "Dark": {"bg": "#0f0f12", "card": "#1a1a21", "text": "#ffffff", "subtext": "#9ca3af", "border": "#2d2d3a"},
    "Light": {"bg": "#f9fafb", "card": "#ffffff", "text": "#111827", "subtext": "#6b7280", "border": "#e5e7eb"}
}

# Metric Card Colors (Light, Dark)
ACCENT_BLUE = ("#2563eb", "#3b82f6")
DANGER_RED = ("#dc2626", "#ef4444")
SUCCESS_GREEN = ("#16a34a", "#10b981")
WARNING_ORANGE = ("#ea580c", "#f59e0b")

# --- CUSTOM TABLE BADGE COLORS ---
# Format: {"bg": (LightModeHex, DarkModeHex), "text": (LightModeHex, DarkModeHex)}

CLASS_COLORS = {
    "Normal": {"bg": ("#dcfce7", "#064e3b"), "text": ("#166534", "#34d399")},
    "DDoS": {"bg": ("#fee2e2", "#7f1d1d"), "text": ("#991b1b", "#f87171")},
    "Anomaly": {"bg": ("#ffedd5", "#78350f"), "text": ("#9a3412", "#fbbf24")}
}

ACTION_COLORS = {
    "Allowed": {"border": ("#86efac", "#059669"), "text": ("#15803d", "#34d399")},
    "Blocked": {"border": ("#fca5a5", "#dc2626"), "text": ("#b91c1c", "#f87171")},
    "Dropped": {"border": ("#d1d5db", "#4b5563"), "text": ("#374151", "#9ca3af")}
}

VECTOR_COLORS = {
    "TCP SYN Flood": {"bg": ("#ffedd5", "#78350f"), "text": ("#9a3412", "#fbbf24")},
    "UDP Flood": {"bg": ("#e0f2fe", "#0c4a6e"), "text": ("#0369a1", "#38bdf8")},
    "ICMP Flood": {"bg": ("#fce7f3", "#831843"), "text": ("#be185d", "#f472b6")},
    "—": {"bg": ("transparent", "transparent"), "text": ("#6b7280", "#9ca3af")}
}

# Add this to the bottom of styles.py
PRIORITY_COLORS = {
    "Low": {"text": ("#6b7280", "#9ca3af")},       # Muted Gray
    "Medium": {"text": ("#ea580c", "#f59e0b")},    # Warning Orange
    "High": {"text": ("#dc2626", "#ef4444")}       # Danger Red
}