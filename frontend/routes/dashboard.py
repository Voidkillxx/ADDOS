"""
frontend/routes/dashboard.py — Dashboard page route
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from frontend.config import BACKEND_API, POLL_INTERVAL_MS, GRAPH_LIVE_POINTS, MAX_LOG_ROWS

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request":  request,
            "api_url":  BACKEND_API,
            "poll_ms":  POLL_INTERVAL_MS,
            "max_pts":  GRAPH_LIVE_POINTS,
            "max_log":  MAX_LOG_ROWS,
        },
    )