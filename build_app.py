#!/usr/bin/env python
"""Build Argus.exe — a single double-clickable ARGUS desktop app.

Bundles argus_app.py (the native window + the stdlib web console + all data
files) into one executable with the ARGUS taskbar icon.

    pip install pyinstaller pywebview pillow
    python build_app.py

Output: dist/Argus.exe  (Windows)  /  dist/Argus  (macOS, Linux)

Notes
  * Run this ON the target OS — PyInstaller does not cross-compile. Build the
    Windows .exe inside your Windows 11 VM.
  * The web console + dataset are read at runtime, so they're bundled as data.
  * `anthropic` is only needed if you use the Claude provider; it's collected if
    present, skipped if not.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEP = ";" if sys.platform.startswith("win") else ":"   # PyInstaller --add-data sep


def ensure_icon() -> Path | None:
    ico = ROOT / "assets" / "argus.ico"
    if ico.exists():
        return ico
    try:
        import build_icon
        build_icon.main()
    except Exception as e:
        print(f"[build] icon generation skipped ({e}); building without a custom icon")
        return None
    return ico if ico.exists() else None


def main() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit("PyInstaller required:  pip install pyinstaller pywebview pillow")

    icon = ensure_icon()

    # data files the running app needs (path_on_disk, dest_dir_in_bundle)
    data = [
        (ROOT / "web" / "static", "web/static"),
        (ROOT / "dataset", "dataset"),
        (ROOT / "rules", "rules"),
    ]
    if icon:
        data.append((ROOT / "assets", "assets"))

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "Argus",
        "--onefile",
        "--windowed",                # no console window on Windows/macOS
        "--collect-all", "webview",  # pywebview ships JS/backends it needs at runtime
    ]
    if icon:
        args += ["--icon", str(icon)]
    for src, dest in data:
        if src.exists():
            args += ["--add-data", f"{src}{SEP}{dest}"]
    # anthropic is optional — only bundle it if installed
    try:
        import anthropic  # noqa: F401
        args += ["--collect-submodules", "anthropic"]
    except ImportError:
        pass
    args.append(str(ROOT / "argus_app.py"))

    print("[build] running PyInstaller…\n  " + " ".join(args))
    subprocess.run(args, check=True, cwd=str(ROOT))
    exe = ROOT / "dist" / ("Argus.exe" if sys.platform.startswith("win") else "Argus")
    print(f"\n[build] done -> {exe}")
    print("[build] double-click it, or run it; the ARGUS window opens with its own taskbar icon.")


if __name__ == "__main__":
    main()
