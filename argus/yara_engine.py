"""YARA scanning for ARGUS — static, never executes the sample.

Prefers `yara-python` if installed; otherwise shells out to the `yara` CLI
binary. Degrades gracefully to "no matches / unavailable" when neither is
present, so the rest of the pipeline keeps working. Rules = every `*.yar` in
config.YARA_RULES_DIR.
"""
from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path
from shutil import which

import config

_compiled = None  # cached yara-python compiled rules


@lru_cache(maxsize=1)
def available() -> tuple[bool, str]:
    """Return (usable, how) — how is 'yara-python', a CLI binary name, or a reason."""
    try:
        import yara  # noqa: F401
        return True, "yara-python"
    except Exception:
        pass
    for b in (config.YARA_BIN, "yara64", "yara"):
        if which(b):
            return True, b
    return False, "yara not installed (pip install yara-python, or install the yara binary)"


def _rule_files() -> list[Path]:
    d = config.YARA_RULES_DIR
    files = (sorted(d.glob("*.yar")) + sorted(d.glob("*.yara"))) if d.exists() else []
    # Add rules from ENABLED community sources (staged sources are excluded).
    try:
        from . import rules_fetch
        files += rules_fetch.active_community_files()
    except Exception:
        pass
    return files


def reset_cache() -> None:
    """Drop cached compiled rules (call after fetch/enable/disable in-process)."""
    global _compiled
    _compiled = None
    available.cache_clear()


def _load_python_rules():
    import yara
    rf = _rule_files()
    if not rf:
        return None
    # Rule-file stems can collide across community sources; make each namespace
    # unique so a name clash doesn't drop a whole file.
    files, seen = {}, {}
    for p in rf:
        ns = p.stem
        seen[ns] = seen.get(ns, 0) + 1
        if seen[ns] > 1:
            ns = f"{ns}_{seen[ns]}"
        files[ns] = str(p)
    try:
        return ("single", yara.compile(filepaths=files))
    except yara.Error:
        # One broken/duplicate community rule would otherwise poison the entire
        # compile and silently disable ALL detection. Fall back to per-file
        # compilation, skipping only the offenders.
        compiled = []
        for path in files.values():
            try:
                compiled.append(yara.compile(filepath=path))
            except yara.Error:
                continue
        return ("multi", compiled)


def scan_file(path: str | Path) -> list[str]:
    """Return the names of YARA rules that matched the file (static scan)."""
    ok, how = available()
    if not ok or not _rule_files():
        return []
    path = str(path)
    if how == "yara-python":
        global _compiled
        try:
            if _compiled is None:
                _compiled = _load_python_rules()
            if not _compiled:
                return []
            kind, obj = _compiled
            if kind == "single":
                return [m.rule for m in obj.match(path)]
            names = []
            for c in obj:  # multi: aggregate matches across per-file compiles
                try:
                    names.extend(m.rule for m in c.match(path))
                except Exception:
                    continue
            return sorted(set(names))
        except Exception:
            return []
    # CLI fallback: `yara <rulefile> <target>` prints "<rule> <path>" per match
    names: list[str] = []
    for rf in _rule_files():
        try:
            r = subprocess.run([how, str(rf), path], capture_output=True, text=True, timeout=60)
            for line in r.stdout.splitlines():
                tok = line.split()
                if tok:
                    names.append(tok[0])
        except Exception:
            continue
    return sorted(set(names))


def status() -> dict:
    ok, how = available()
    return {"available": ok, "engine": how if ok else None, "reason": None if ok else how,
            "rules": len(_rule_files()), "rules_dir": str(config.YARA_RULES_DIR)}
