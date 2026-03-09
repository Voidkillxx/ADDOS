"""
frontend/app.py — FastAPI application factory
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from frontend.routes.dashboard import router as dashboard_router

BASE_DIR = Path(__file__).parent


def create_app() -> FastAPI:
    app = FastAPI(title="A-DDoS Dashboard", docs_url=None, redoc_url=None)

    # Static files (CSS, JS)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    # Jinja2 templates
    app.state.templates = Jinja2Templates(directory=BASE_DIR / "templates")

    # Routes
    app.include_router(dashboard_router)

    return app