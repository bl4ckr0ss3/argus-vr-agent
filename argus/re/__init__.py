"""ARGUS reverse-engineering workspace backend.

A browser IDE for static RE — Sections / Functions / Symbols rail, a
disassembly view (capstone), a rule-based pseudocode decompiler, a hex view,
and an assembler (keystone). Parses both PE and ELF with pure-stdlib struct
code; capstone/keystone are OPTIONAL (the panel degrades gracefully and tells
the user to `pip install` them).

This is HOST-side analysis, not detonation — it never executes the sample.
"""
from __future__ import annotations

from .session import (
    load_binary,
    get_session,
    HAVE_CAPSTONE,
    HAVE_KEYSTONE,
)

__all__ = ["load_binary", "get_session", "HAVE_CAPSTONE", "HAVE_KEYSTONE"]
