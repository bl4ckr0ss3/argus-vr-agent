#!/usr/bin/env python
"""ARGUS Desktop — Windows system-tray application.

Usage:
    python  argus_tray.py       # console + tray icon
    pythonw argus_tray.py       # tray icon only (no console)

Right-click the tray icon to open the web console, start/stop the server,
view status, or quit. The web server runs in a background thread.

Optional tray dependencies (gracefully skipped if absent):
    pip install pystray pillow
"""
from __future__ import annotations

import os
import sys
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

HOST = os.environ.get("ARGUS_HOST", "127.0.0.1")
PORT = int(os.environ.get("ARGUS_PORT", "8765"))
CONSOLE_URL = f"http://{HOST}:{PORT}"

_httpd = None
_icon = None
_tray_available = False


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


def _start_server() -> bool:
    global _httpd
    if _httpd is not None:
        return True
    try:
        from web.server import create_server
        _httpd = create_server(HOST, PORT)
        t = threading.Thread(target=_httpd.serve_forever, daemon=True, name="argus-web")
        t.start()
        return True
    except Exception as e:
        print(f"[ARGUS] failed to start web server: {e}")
        return False


def _stop_server() -> bool:
    global _httpd
    if _httpd is None:
        return True
    try:
        _httpd.shutdown()
        _httpd.server_close()
        _httpd = None
        return True
    except Exception as e:
        print(f"[ARGUS] failed to stop: {e}")
        return False


def _server_running() -> bool:
    return _httpd is not None


def _make_icon():
    """Generate a 64x64 ARGUS system-tray icon (scope/reticle + 'A')."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    green = (57, 255, 139, 255)
    bg = (8, 10, 11, 255)

    draw.ellipse((2, 2, 61, 61), fill=bg, outline=green, width=2)
    draw.ellipse((16, 16, 48, 48), outline=green, width=2)
    draw.ellipse((28, 28, 36, 36), fill=green)

    for d in (-18, 19):
        draw.line((32 + d, 30, 32 + d, 34), fill=green, width=1)
        draw.line((30, 32 + d, 34, 32 + d), fill=green, width=1)

    return img


def _status_text() -> str:
    running = _server_running()
    from web.server import backend_status
    st = backend_status()
    lines = [
        f"ARGUS v0.1",
        f"Server:  {'RUNNING' if running else 'STOPPED'}",
        f"Port:    {PORT}",
        f"Model:   {st['provider']}/{st['model']}",
        f"API:     {'ready' if st['ready'] else st.get('error', '?')}",
    ]
    return "\n".join(lines)


def _tray_setup():
    global _icon, _tray_available
    try:
        import pystray
    except ImportError:
        return

    img = _make_icon()
    if img is None:
        print("[ARGUS] Pillow not available — tray icon disabled (pip install pillow)")
        return

    _tray_available = True

    def _on_open():
        webbrowser.open(CONSOLE_URL)

    def _on_start():
        if _start_server():
            _icon.notify(f"ARGUS running at {CONSOLE_URL}")
            _icon.update_menu()

    def _on_stop():
        _stop_server()
        _icon.notify("ARGUS server stopped")
        _icon.update_menu()

    def _on_status():
        _icon.notify(_status_text())

    def _menu(icon):
        running = _server_running()
        import pystray as ps
        return ps.Menu(
            ps.MenuItem("Open Console", _on_open, enabled=running, default=True),
            ps.Menu.SEPARATOR,
            ps.MenuItem("Stop Server", _on_stop, visible=running),
            ps.MenuItem("Start Server", _on_start, visible=not running),
            ps.Menu.SEPARATOR,
            ps.MenuItem("Status", _on_status),
            ps.MenuItem("Quit", lambda: _do_quit()),
        )

    def _do_quit():
        _stop_server()
        if _icon:
            _icon.stop()

    _icon = pystray.Icon("argus", img, "ARGUS VR Agent", menu=pystray.Menu(_menu))
    print(f"[ARGUS] Tray icon active — right-click to control.")
    print(f"[ARGUS] Web console: {CONSOLE_URL}")
    _icon.run()


def main():
    print("ARGUS Desktop — starting...")
    _load_dotenv()

    if not _start_server():
        print("[ARGUS] Server failed to start. Check your .env configuration.")
        return

    tray_thread = threading.Thread(target=_tray_setup, daemon=True, name="argus-tray")
    tray_thread.start()

    if _tray_available:
        # tray icon handles its own event loop from the thread above
        pass
    else:
        print("[ARGUS] Tray icon not available (pip install pystray pillow).")
        print("[ARGUS] Press Ctrl+C in this console to stop.")

    try:
        import time
        while _server_running():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[ARGUS] Shutting down...")
        _stop_server()


if __name__ == "__main__":
    main()
