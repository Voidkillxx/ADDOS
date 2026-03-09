"""
frontend/config.py — Frontend configuration
"""

# Backend API base URL (your existing Flask/FastAPI backend)
BACKEND_API = "http://127.0.0.1:5000"

# Dashboard server settings
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8080

# Chart settings
GRAPH_LIVE_POINTS = 30
POLL_INTERVAL_MS  = 2000
MAX_LOG_ROWS      = 100