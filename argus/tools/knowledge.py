"""retrieve_knowledge — RAG over the vault-derived corpus.

This is the tool that makes ARGUS *Muhammed's* agent rather than a generic one: it
surfaces prior findings, methodology, and dead ends from the second brain so the
agent reuses hard-won context instead of re-deriving it.
"""
from __future__ import annotations

from ..rag import BM25Index
from .base import Tool


def make_tool(index: BM25Index) -> Tool:
    def handler(inp: dict) -> str:
        q = (inp.get("query") or "").strip()
        k = int(inp.get("k", 4))
        if not q:
            return "ERROR: query is required."
        hits = index.query(q, k=max(1, min(k, 8)))
        if not hits:
            return f"No matching notes in the knowledge base for: {q!r}"
        out = [f"Top {len(hits)} knowledge-base hits for: {q!r}\n"]
        for i, h in enumerate(hits, 1):
            meta = h.get("meta", {})
            src = meta.get("source", "?")
            tgt = meta.get("target", "")
            tag = f" · target={tgt}" if tgt else ""
            out.append(f"--- [{i}] score={h.get('score')} · {src}{tag} ---")
            out.append(h.get("text", "").strip())
            out.append("")
        return "\n".join(out)

    return Tool(
        name="retrieve_knowledge",
        description=(
            "Search Muhammed's vulnerability-research second brain (past findings, "
            "methodology, target notes, dead ends) for context relevant to the "
            "current hunt. ALWAYS call this before starting analysis on a target "
            "and whenever you hit a decision point, so you reuse prior work "
            "instead of repeating it. Returns the most relevant note excerpts."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What you want to know, e.g. 'DLL planting SYSTEM service search order' or 'named pipe DACL LPE'.",
                },
                "k": {
                    "type": "integer",
                    "description": "Number of note excerpts to return (1-8, default 4).",
                },
            },
            "required": ["query"],
        },
        handler=handler,
    )
