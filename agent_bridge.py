#!/usr/bin/env python
"""agent_bridge — relay a message into the OpenCode DeepSeek session and log the reply.

Drives the OpenCode CLI headlessly (`opencode run -s <session> --pure --auto`) so
the Claude (Opus 5) session and the OpenCode (DeepSeek V4-pro) session can hold an
automated back-and-forth without anyone copy-pasting. Every exchange is appended to
AGENT_CHANNEL.md so you can watch it live from another terminal:

    # PowerShell
    Get-Content AGENT_CHANNEL.md -Wait
    # Git-bash / WSL
    tail -f AGENT_CHANNEL.md

Usage:
    python agent_bridge.py "message from Opus to DeepSeek"
    python agent_bridge.py --from DeepSeek "...(rarely needed)"
    echo "message" | python agent_bridge.py -      # read message from stdin

Env overrides:
    ARGUS_OC_SESSION   OpenCode session id       (default: the V4-pro session)
    ARGUS_OC_MODEL     provider/model            (default: deepseek/deepseek-v4-pro)
    ARGUS_OC_TIMEOUT   per-call seconds          (default: 300)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHANNEL = ROOT / "AGENT_CHANNEL.md"

SESSION = os.environ.get("ARGUS_OC_SESSION", "ses_04d30843dffeN4Lr2aLUvIdxgv")
MODEL = os.environ.get("ARGUS_OC_MODEL", "deepseek/deepseek-v4-pro")
TIMEOUT = int(os.environ.get("ARGUS_OC_TIMEOUT", "300"))

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _opencode_env() -> dict:
    env = dict(os.environ)
    # make sure the npm-global opencode shim is reachable on Windows
    npm = str(Path(os.environ.get("APPDATA", "")) / "npm")
    if npm and npm not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + os.pathsep + npm
    return env


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log_turn(speaker: str, text: str) -> None:
    CHANNEL.parent.mkdir(parents=True, exist_ok=True)
    if not CHANNEL.exists():
        CHANNEL.write_text(
            "# ARGUS agent channel (live)\n\n"
            "Automated relay between the Claude Opus 5 session and the OpenCode "
            "DeepSeek V4-pro session. Watch with `Get-Content AGENT_CHANNEL.md -Wait` "
            "(PowerShell) or `tail -f AGENT_CHANNEL.md`.\n\n---\n",
            encoding="utf-8",
        )
    with CHANNEL.open("a", encoding="utf-8") as fh:
        fh.write(f"\n### [{_stamp()}] {speaker}\n\n{text.strip()}\n")


def send_to_deepseek(message: str) -> str:
    """Forward `message` into the OpenCode session; return DeepSeek's reply text."""
    cmd = [
        "opencode", "run",
        "-s", SESSION,
        "-m", MODEL,
        "--pure", "--auto",
    ]
    # opencode on Windows is a .cmd shim -> run via shell for PATHEXT resolution
    try:
        proc = subprocess.run(
            cmd + [message],
            capture_output=True, text=True, timeout=TIMEOUT,
            env=_opencode_env(), stdin=subprocess.DEVNULL,
            shell=(os.name == "nt"),
        )
    except subprocess.TimeoutExpired:
        return f"[bridge] OpenCode timed out after {TIMEOUT}s"
    except OSError as e:
        return f"[bridge] failed to launch opencode: {e}"
    out = _ANSI.sub("", proc.stdout or "").strip()
    if not out:
        err = _ANSI.sub("", proc.stderr or "").strip()
        return f"[bridge] empty reply (exit {proc.returncode}). stderr: {err[:400]}"
    return out


def main(argv: list[str]) -> int:
    speaker = "Claude · Opus 5"
    args = argv[:]
    if args and args[0] == "--from":
        speaker, args = args[1], args[2:]
    if args == ["-"]:
        message = sys.stdin.read().strip()
    else:
        message = " ".join(args).strip()
    if not message:
        print("usage: python agent_bridge.py \"message\"", file=sys.stderr)
        return 2

    log_turn(speaker, message)
    print(f"[bridge] {speaker} -> DeepSeek V4-pro (session {SESSION[:16]}…) …", file=sys.stderr)
    reply = send_to_deepseek(message)
    log_turn("OpenCode · DeepSeek V4-pro", reply)
    print("\n===== DeepSeek reply =====\n")
    print(reply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
