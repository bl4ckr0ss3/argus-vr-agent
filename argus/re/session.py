"""RE session — load a binary once, cache the analysis, serve slices to the UI.

A session is keyed by the sha256 of the file so re-opening the same sample is
instant. Everything here is read-only static analysis; nothing executes.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from . import container as C
from . import disasm as D
from . import functions as F
from . import pseudo as P

HAVE_CAPSTONE = D.HAVE_CAPSTONE
HAVE_KEYSTONE = D.HAVE_KEYSTONE

_SESSIONS: dict[str, "Session"] = {}
_MAX_BYTES = 64 * 1024 * 1024  # 64 MB guard
# Bound the session cache so analyzing many distinct binaries doesn't leak memory
# indefinitely. Sessions are cheap to reload (pure parse on re-open), so evicting
# the least-recently-used ones is safe — the UI just re-parses on demand.
_SESSION_CACHE_MAX = 40
_SESSION_ORDER: list[str] = []  # sha256 of sessions, most-recent first


class Session:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.binary = C.parse(data)
        self.md = None
        self.functions: list[dict] = []
        self.xrefs: dict[str, list[int]] = {}
        if self.binary:
            self.md = D.make_engine(self.binary["arch"], self.binary["bits"])
            disc = F.discover(self.binary, self.data, self.md)
            self.functions = disc["functions"]
            self.xrefs = disc["xrefs"]

    # -- summary for the initial /load response ---------------------------
    def summary(self) -> dict:
        b = self.binary or {}
        return {
            "id": self.sha256,
            "name": self.name,
            "sha256": self.sha256,
            "size": len(self.data),
            "format": b.get("format", "unknown"),
            "arch": b.get("arch", "?"),
            "bits": b.get("bits", 0),
            "entry": b.get("entry", 0),
            "image_base": b.get("image_base", 0),
            "have_disasm": self.md is not None,
            "have_capstone": HAVE_CAPSTONE,
            "have_keystone": HAVE_KEYSTONE,
            "counts": {
                "sections": len(b.get("sections", [])),
                "functions": len(self.functions),
                "symbols": len(b.get("symbols", [])),
                "imports": len(b.get("imports", [])),
                "exports": len(b.get("exports", [])),
            },
            "parse_error": None if self.binary else "unrecognized format (not PE/ELF)",
        }

    def sections(self) -> list[dict]:
        return self.binary["sections"] if self.binary else []

    def symbols(self) -> list[dict]:
        return self.binary["symbols"] if self.binary else []

    def imports(self) -> list[dict]:
        return self.binary["imports"] if self.binary else []

    def exports(self) -> list[dict]:
        return self.binary["exports"] if self.binary else []

    # -- disassembly / decompile ------------------------------------------
    def _find_func(self, addr: int) -> dict | None:
        for f in self.functions:
            if f["addr"] == addr:
                return f
        return None

    def disasm_func(self, addr: int) -> dict:
        if not self.binary or self.md is None:
            return {"rows": [], "error": self._no_disasm()}
        rows = F.function_disasm(self.binary, self.data, self.md, addr)
        f = self._find_func(addr)
        return {"addr": addr, "name": (f or {}).get("name", f"FUN_{addr:08x}"),
                "rows": rows, "error": None}

    def disasm_at(self, va: int, count: int = 200) -> dict:
        if not self.binary or self.md is None:
            return {"rows": [], "error": self._no_disasm()}
        off = C.va_to_off(self.binary, va)
        if off is None:
            return {"rows": [], "error": f"address {va:#x} not in any mapped section"}
        rows = D.disassemble(self.data, off, va, count, self.md)
        return {"addr": va, "rows": rows, "error": None}

    def decompile(self, addr: int) -> dict:
        if not self.binary:
            return {"lines": [], "error": "no binary parsed"}
        if self.md is None:
            return {"lines": [], "error": self._no_disasm()}
        rows = F.function_disasm(self.binary, self.data, self.md, addr)
        f = self._find_func(addr)
        name = (f or {}).get("name", f"FUN_{addr:08x}")
        out = P.decompile(rows, name, self.binary["arch"])
        out["addr"] = addr
        out["name"] = name
        out["engine"] = "rule-based"
        out["error"] = None
        return out

    def cfg(self, addr: int) -> dict:
        if not self.binary or self.md is None:
            return {"blocks": [], "error": self._no_disasm()}
        rows = F.function_disasm(self.binary, self.data, self.md, addr)
        blocks = F.basic_blocks(rows)
        return {"addr": addr, "blocks": blocks, "error": None}

    def xrefs_to(self, addr: int) -> list[int]:
        return self.xrefs.get(str(addr), [])

    def _no_disasm(self) -> str:
        return ("capstone not installed — pip install capstone to enable "
                "disassembly/decompilation (sections, hex, strings still work)")

    # -- hex --------------------------------------------------------------
    def hexdump(self, off: int, length: int = 512) -> dict:
        off = max(0, min(off, len(self.data)))
        length = max(0, min(length, 4096))
        chunk = self.data[off:off + length]
        rows = []
        for i in range(0, len(chunk), 16):
            line = chunk[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in line)
            asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in line)
            rows.append({"off": off + i, "hex": hexpart, "ascii": asciipart})
        va0 = C.off_to_va(self.binary, off) if self.binary else None
        return {"off": off, "va": va0, "rows": rows, "total": len(self.data)}

    # -- strings ----------------------------------------------------------
    def strings(self, minlen: int = 5, limit: int = 3000) -> list[dict]:
        out = []
        for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, self.data):
            off = m.start()
            va = C.off_to_va(self.binary, off) if self.binary else None
            out.append({"off": off, "va": va,
                        "text": m.group().decode("latin1", "ignore")[:200]})
            if len(out) >= limit:
                break
        return out

    def search(self, needle: str, limit: int = 500) -> list[dict]:
        out = []
        if not needle:
            return out
        raw = needle.encode("latin1", "ignore")
        start = 0
        while len(out) < limit:
            idx = self.data.find(raw, start)
            if idx == -1:
                break
            va = C.off_to_va(self.binary, idx) if self.binary else None
            out.append({"off": idx, "va": va})
            start = idx + 1
        return out


# ===========================================================================
# module API
# ===========================================================================
def load_binary(name: str, data: bytes | None = None, path: str | None = None) -> dict:
    if data is None:
        if not path:
            return {"error": "no data or path"}
        p = Path(path)
        if not p.is_file():
            return {"error": f"no such file: {path}"}
        if p.stat().st_size > _MAX_BYTES:
            return {"error": f"file too large (> {_MAX_BYTES // (1024*1024)} MB)"}
        data = p.read_bytes()
        name = name or p.name
    if len(data) > _MAX_BYTES:
        return {"error": "file too large"}
    sess = Session(name or "sample", data)
    _SESSIONS[sess.sha256] = sess
    # LRU bookkeeping: touch (move to front) + evict LRU when over the bound
    if sess.sha256 in _SESSION_ORDER:
        _SESSION_ORDER.remove(sess.sha256)
    _SESSION_ORDER.insert(0, sess.sha256)
    while len(_SESSION_ORDER) > _SESSION_CACHE_MAX:
        old = _SESSION_ORDER.pop()
        _SESSIONS.pop(old, None)
    return sess.summary()


def get_session(sid: str) -> Session | None:
    sess = _SESSIONS.get(sid)
    if sess is not None and sid in _SESSION_ORDER:
        # move to front on access (cheap list remove+insert; list is small)
        _SESSION_ORDER.remove(sid)
        _SESSION_ORDER.insert(0, sid)
    return sess
