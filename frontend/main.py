"""
frontend/main.py — Entry point
Run: python3 -m frontend.main
  OR: python3 frontend/main.py
"""
import threading
import time
import webbrowser
import uvicorn
from frontend.app import create_app

HOST = "127.0.0.1"
PORT = 8080


def _open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://{HOST}:{PORT}")


if __name__ == "__main__":
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(create_app(), host=HOST, port=PORT)