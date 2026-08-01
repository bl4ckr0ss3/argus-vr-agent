"""yara_scan tool — run the YARA rule set against a file/dir (static)."""
from __future__ import annotations

from pathlib import Path

import config
from .. import yara_engine
from .base import Tool, cap


def make_yara_scan() -> Tool:
    def handler(inp: dict) -> str:
        raw = (inp.get("path") or "").strip()
        if not raw:
            return "ERROR: path is required."
        p = Path(raw).expanduser()
        if not p.exists():
            return f"ERROR: no such path: {p}"
        ok, how = yara_engine.available()
        if not ok:
            return f"YARA unavailable: {how}"
        targets = [f for f in p.rglob("*") if f.is_file()][:40] if p.is_dir() else [p]
        lines = [f"YARA ({how}) · rules dir {config.YARA_RULES_DIR}"]
        for f in targets:
            hits = yara_engine.scan_file(f)
            lines.append(f"  {f.name}: {', '.join(hits) if hits else '(no matches)'}")
        return cap("\n".join(lines), config.TOOL_OUTPUT_CAP)

    return Tool(
        name="yara_scan",
        description=(
            "Run the local YARA rule set (rules/*.yar) against a file or every file "
            "in a directory. Static — never executes the sample. Returns matched rule "
            "names per file."
        ),
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File or quarantine directory to scan."}},
            "required": ["path"],
        },
        handler=handler,
    )
