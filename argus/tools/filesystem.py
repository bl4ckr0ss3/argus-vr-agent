"""Read-only filesystem inspection tools.

These let ARGUS look at a target's files, directory layout, and source/config
without ever mutating anything. All output is capped so a single call cannot
flood the model's context.
"""
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

import config
from .base import Tool, cap


def _safe_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw))).resolve()


def make_read_file() -> Tool:
    def handler(inp: dict) -> str:
        raw = inp.get("path", "")
        if not raw:
            return "ERROR: path is required."
        p = _safe_path(raw)
        if not p.exists():
            return f"ERROR: no such file: {p}"
        if p.is_dir():
            return f"ERROR: {p} is a directory — use list_dir."
        max_bytes = int(inp.get("max_bytes", config.TOOL_OUTPUT_CAP))
        try:
            data = p.read_bytes()[: max_bytes + 1]
        except OSError as e:
            return f"ERROR reading {p}: {e}"
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            # Binary file: give a hex-ish preview instead of garbage.
            preview = data[:512].hex(" ")
            return f"[binary file, {p.stat().st_size} bytes] first 512 bytes hex:\n{preview}"
        return cap(text, max_bytes)

    return Tool(
        name="read_file",
        description="Read a text (or preview a binary) file from disk. Read-only.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or ~/env path to read."},
                "max_bytes": {"type": "integer", "description": f"Cap on bytes returned (default {config.TOOL_OUTPUT_CAP})."},
            },
            "required": ["path"],
        },
        handler=handler,
    )


def make_list_dir() -> Tool:
    def handler(inp: dict) -> str:
        raw = inp.get("path", ".")
        p = _safe_path(raw)
        if not p.exists():
            return f"ERROR: no such directory: {p}"
        if not p.is_dir():
            return f"ERROR: {p} is a file — use read_file."
        entries = []
        try:
            for child in sorted(p.iterdir()):
                try:
                    if child.is_dir():
                        entries.append(f"[dir]  {child.name}/")
                    else:
                        entries.append(f"[file] {child.name}  ({child.stat().st_size} bytes)")
                except OSError:
                    entries.append(f"[?]    {child.name}")
        except OSError as e:
            return f"ERROR listing {p}: {e}"
        return cap(f"{p}\n" + "\n".join(entries), config.TOOL_OUTPUT_CAP)

    return Tool(
        name="list_dir",
        description="List the contents of a directory. Read-only.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Directory to list."}},
            "required": ["path"],
        },
        handler=handler,
    )


def make_grep() -> Tool:
    def handler(inp: dict) -> str:
        pattern = inp.get("pattern", "")
        if not pattern:
            return "ERROR: pattern is required."
        root = _safe_path(inp.get("path", "."))
        glob = inp.get("glob", "*")
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return f"ERROR: bad regex: {e}"
        if root.is_file():
            files = [root]
        else:
            files = [
                f for f in root.rglob("*")
                if f.is_file() and fnmatch.fnmatch(f.name, glob)
            ]
        matches: list[str] = []
        scanned = 0
        for f in files:
            if len(matches) >= 200:
                break
            scanned += 1
            try:
                with f.open(encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if rx.search(line):
                            matches.append(f"{f}:{lineno}: {line.rstrip()[:300]}")
                            if len(matches) >= 200:
                                break
            except OSError:
                continue
        header = f"Scanned {scanned} file(s) under {root} (glob={glob}); {len(matches)} match line(s):\n"
        return cap(header + "\n".join(matches) if matches else header + "(no matches)", config.TOOL_OUTPUT_CAP)

    return Tool(
        name="grep",
        description="Regex-search files under a path (recursive), optionally filtered by a filename glob. Read-only.",
        input_schema={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Python regex (case-insensitive)."},
                "path": {"type": "string", "description": "File or directory root to search."},
                "glob": {"type": "string", "description": "Filename glob filter, e.g. '*.c' or '*.js' (default '*')."},
            },
            "required": ["pattern", "path"],
        },
        handler=handler,
    )
