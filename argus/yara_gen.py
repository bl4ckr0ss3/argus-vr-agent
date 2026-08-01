"""Generate YARA rules from analyzed samples, and collect them.

Auto-derives a candidate rule from a sample's distinctive static features
(printable strings + PE magic + hash) so a family ARGUS just triaged can be
caught statically next time. This is the self-improving half of detection.

SAFETY / collection model — generated rules are STAGED, not live:
  * config.YARA_RULES_DIR            <- active rules the scanner loads (top level)
  * config.YARA_RULES_DIR/generated  <- candidates; the scanner does NOT load these
A candidate must be reviewed and `promote()`d into the active dir before it
fires. Same human-gate as publishing: an over-broad auto-rule can't start
throwing false positives on its own.

Pure stdlib. No sample is executed - this reads bytes only.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

import config

_MIN_LEN = 6
_MAX_STRINGS = 20
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_LEN)
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_LEN)
_NAME_SANITIZE = re.compile(r"[^A-Za-z0-9_]+")

# Substrings that make a string worth keeping (distinctive / behavioral).
_BOOST = ("http://", "https://", "://", ".onion", "\\", "cmd.exe", "powershell",
          "rundll32", "schtasks", "regsvr32", "createremotethread", "virtualalloc",
          "writeprocessmemory", "wininet", "urlmon", "\\run", "currentversion",
          "appdata", "temp\\", "programdata", "mutex", "bitcoin", "wallet",
          "ransom", "encrypt", "decrypt", "beacon", "c2", "bot", "inject",
          "vssadmin", "bcdedit", "shadowcopy", ".ps1", ".vbs", ".bat", "-enc")
# Common boilerplate / system noise - too generic to be distinctive.
_STOP = ("this program cannot be run in dos mode", "kernel32.dll", "user32.dll",
         "ntdll.dll", "msvcrt.dll", "advapi32.dll", "ole32.dll", "gdi32.dll",
         "getprocaddress", "loadlibrary", "microsoft", "windows", "visual c++",
         "mscoree.dll", ".text", ".data", ".rdata", ".rsrc", ".reloc",
         "assembly", "richedit", "comctl32")


def _generated_dir() -> Path:
    return config.YARA_RULES_DIR / "generated"


def _sanitize_name(name: str) -> str:
    n = _NAME_SANITIZE.sub("_", name).strip("_")
    if not n or n[0].isdigit():
        n = "R_" + n
    return n[:64]


def _decode(b: bytes, wide: bool) -> str:
    if wide:
        b = b[::2]  # drop the interleaved NULs of UTF-16LE
    return b.decode("ascii", "ignore")


def extract_strings(data: bytes) -> list[tuple[str, bool]]:
    """Printable ASCII + UTF-16LE strings, as (text, is_wide) with dups removed."""
    seen, out = set(), []
    for m in _ASCII_RE.finditer(data):
        s = _decode(m.group(), False)
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append((s, False))
    for m in _WIDE_RE.finditer(data):
        s = _decode(m.group(), True)
        if len(s) >= _MIN_LEN and s.lower() not in seen:
            seen.add(s.lower())
            out.append((s, True))
    return out


def _score(s: str) -> int:
    low = s.lower()
    if any(stop in low for stop in _STOP):
        return -1
    if len(s) > 120 or len(s) < _MIN_LEN:
        return -1
    if not re.search(r"[A-Za-z]", s):     # pure punctuation/digits: not distinctive
        return -1
    score = 1
    score += sum(3 for b in _BOOST if b in low)
    if re.search(r"[A-Za-z].*\d|\d.*[A-Za-z]", s):  # mixed alnum -> looks like a token
        score += 1
    if 10 <= len(s) <= 60:
        score += 1
    return score


def _pick(strings: list[tuple[str, bool]], limit: int = _MAX_STRINGS) -> list[tuple[str, bool]]:
    scored = [(sc, s, w) for (s, w) in strings if (sc := _score(s)) > 0]
    scored.sort(key=lambda t: (-t[0], -len(t[1])))
    return [(s, w) for _, s, w in scored[:limit]]


def _yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def generate_rule(sample_path, name: str | None = None,
                  meta: dict | None = None) -> dict:
    """Build a candidate YARA rule from a sample. Returns
    {name, text, strings_used, sha256, error?}. Never executes the sample."""
    p = Path(sample_path)
    if not p.exists():
        return {"error": f"no such file: {p}"}
    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    rule_name = "ARGUS_" + _sanitize_name(name or p.stem or sha[:12])

    picked = _pick(extract_strings(data))
    if len(picked) < 2:
        return {"error": "too few distinctive strings to build a reliable rule",
                "sha256": sha, "name": rule_name}

    is_pe = data[:2] == b"MZ"
    meta = meta or {}
    when = datetime.now().strftime("%Y-%m-%d")
    size_cap = max(1, (len(data) // (1024 * 1024)) + 1)
    hit = min(len(picked), max(3, len(picked) // 2))

    lines = [f"rule {rule_name}", "{", "    meta:",
             '        author = "ARGUS auto-gen"',
             f'        date = "{when}"',
             f'        description = "{_yara_escape(meta.get("description", "auto-generated candidate - REVIEW before promoting"))}"',
             f'        sha256 = "{sha}"']
    if meta.get("verdict"):
        lines.append(f'        verdict = "{_yara_escape(str(meta["verdict"]))}"')
    if meta.get("family"):
        lines.append(f'        family = "{_yara_escape(str(meta["family"]))}"')
    lines.append('        status = "candidate"')

    lines.append("    strings:")
    strings_used = []
    for i, (s, wide) in enumerate(picked):
        mod = " wide" if wide else " ascii"
        lines.append(f'        $s{i} = "{_yara_escape(s)}"{mod}')
        strings_used.append(s)

    cond = []
    if is_pe:
        cond.append("uint16(0) == 0x5A4D")
    cond.append(f"filesize < {size_cap}MB")
    cond.append(f"{hit} of ($s*)")
    lines.append("    condition:")
    lines.append("        " + " and ".join(cond))
    lines.append("}")

    return {"name": rule_name, "text": "\n".join(lines) + "\n",
            "strings_used": strings_used, "sha256": sha, "is_pe": is_pe}


def save_generated(rule: dict) -> Path:
    """Write a generated rule to the STAGING dir (not loaded by the scanner)."""
    gen = _generated_dir()
    gen.mkdir(parents=True, exist_ok=True)
    path = gen / f"{rule['name']}.yar"
    path.write_text(rule["text"], encoding="utf-8")
    return path


def list_rules() -> dict:
    """Active (loaded) rules vs. staged candidates."""
    active_dir = config.YARA_RULES_DIR
    active = sorted(p.name for p in active_dir.glob("*.yar")) if active_dir.exists() else []
    active += sorted(p.name for p in active_dir.glob("*.yara")) if active_dir.exists() else []
    gen = _generated_dir()
    generated = sorted(p.name for p in gen.glob("*.yar")) if gen.exists() else []
    return {"active_dir": str(active_dir), "active": active,
            "generated_dir": str(gen), "generated": generated}


def promote(name: str, force: bool = False) -> dict:
    """Move a staged candidate into the active ruleset so the scanner loads it.

    Runs the quality gate first (compile + goodware false-positive scan) and
    refuses a rule that fails, unless force=True."""
    if not name.endswith((".yar", ".yara")):
        name += ".yar"
    src = _generated_dir() / name
    if not src.exists():
        return {"error": f"no staged rule: {name}"}

    quality = None
    if not force:
        from . import rule_quality
        quality = rule_quality.check_file(src)
        if not quality["passed"]:
            return {"error": "quality gate failed: " + "; ".join(quality["reasons"]),
                    "quality": quality, "hint": "review the rule, or override with --force"}

    dst = config.YARA_RULES_DIR / name
    config.YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
    src.replace(dst)
    return {"ok": True, "promoted": name, "path": str(dst), "quality": quality}
