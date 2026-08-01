#!/usr/bin/env python
"""ARGUS Desktop — native application window (Windows / macOS / Linux).

Boots the zero-dependency web console in a background thread and opens it inside
a real native window (via pywebview), so ARGUS shows up as its own application
with its own taskbar entry and icon — not just a browser tab.

    python run.py app          # or:  python argus_app.py
    pythonw argus_app.py       # Windows: no console window

Packaged form (see build_app.py): a single Argus.exe with the ARGUS icon that
double-clicks straight into this window.

Dependency: pywebview (the ONE runtime dep the desktop app adds).
    pip install pywebview
If it isn't installed, this falls back to opening the console in your default
browser and keeping the server alive — nothing is lost, it's just a tab.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

APP_TITLE = "ARGUS · Hunter Deck"
HOST = os.environ.get("ARGUS_HOST", "127.0.0.1")


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _pick_port() -> int:
    """Preferred port if free, else an OS-assigned free one."""
    want = int(os.environ.get("ARGUS_PORT", "8765"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, want))
            return want
        except OSError:
            s.bind((HOST, 0))
            return s.getsockname()[1]


def _wait_ready(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=1):
                return True
        except Exception:
            time.sleep(0.15)
    return False


def _set_win_appid() -> None:
    """Give Windows an explicit AppUserModelID so the taskbar shows our icon,
    not the generic pythonw host icon."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Argus.HunterDeck")
    except Exception:
        pass


def main() -> None:
    _load_dotenv()
    _set_win_appid()

    from web.server import create_server
    port = _pick_port()
    url = f"http://{HOST}:{port}"

    httpd = create_server(HOST, port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True, name="argus-web")
    t.start()

    if not _wait_ready(url):
        print(f"[ARGUS] server did not come up on {url}", file=sys.stderr)

    icon = ROOT / "assets" / "argus.ico"
    try:
        import webview  # pywebview
    except ImportError:
        print("[ARGUS] pywebview not installed — opening in your browser instead.")
        print("        For the native app window:  pip install pywebview")
        print(f"[ARGUS] console: {url}   (Ctrl+C to quit)")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            httpd.shutdown(); httpd.server_close()
        return

    kwargs = {"width": 1320, "height": 860, "min_size": (960, 640)}
    try:
        webview.create_window(APP_TITLE, url, **kwargs)
        # icon is honored by the GTK/QT backends; on Windows the taskbar icon
        # comes from the packaged Argus.exe (see build_app.py).
        start_kwargs = {}
        if icon.exists():
            start_kwargs["icon"] = str(icon)
        try:
            webview.start(**start_kwargs)
        except TypeError:
            webview.start()  # older pywebview without the icon kwarg
    finally:
        httpd.shutdown(); httpd.server_close()


if __name__ == "__main__":
    main()
