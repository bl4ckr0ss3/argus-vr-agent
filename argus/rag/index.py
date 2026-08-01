"""Pure-Python BM25 retriever over the vault-derived corpus.

The corpus is small (dozens of chunks), so we build the index in memory on load
and optionally cache it to disk. Implementing BM25 by hand keeps ARGUS free of
native/embedding dependencies — it runs offline on CPU with only the stdlib.

Corpus format (one JSON object per line in dataset/corpus.jsonl):
    {"id": "...", "text": "...", "meta": {"source": "...", "target": "...", ...}}
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./\\-]+")

# Very small stoplist — VR notes are terse and technical, so we keep almost
# everything (identifiers like "IOCTL", "DACL" are the whole point).
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for",
    "on", "as", "at", "by", "be", "this", "that", "with", "from", "are",
}


def tokenize(text: str) -> list[str]:
    return [t for t in (m.lower() for m in _TOKEN_RE.findall(text)) if t not in _STOP]


@dataclass
class BM25Index:
    """In-memory BM25 over a list of documents."""

    k1: float = 1.5
    b: float = 0.75
    docs: list[dict[str, Any]] = field(default_factory=list)
    _tokenized: list[list[str]] = field(default_factory=list)
    _df: Counter = field(default_factory=Counter)
    _avg_len: float = 0.0

    # --- construction ------------------------------------------------------
    @classmethod
    def from_corpus(cls, corpus_path: str | Path) -> "BM25Index":
        idx = cls()
        path = Path(corpus_path)
        if not path.exists():
            raise FileNotFoundError(
                f"corpus not found at {path} — run `python -m dataset.build_dataset` first"
            )
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    idx.docs.append(json.loads(line))
        idx._build()
        return idx

    def _build(self) -> None:
        self._tokenized = [tokenize(d.get("text", "")) for d in self.docs]
        self._df = Counter()
        for toks in self._tokenized:
            for term in set(toks):
                self._df[term] += 1
        total = sum(len(t) for t in self._tokenized)
        self._avg_len = (total / len(self._tokenized)) if self._tokenized else 0.0

    # --- query -------------------------------------------------------------
    def _idf(self, term: str) -> float:
        n = len(self.docs)
        df = self._df.get(term, 0)
        # BM25+ style idf, floored at 0 so common terms never go negative.
        return max(0.0, math.log(1 + (n - df + 0.5) / (df + 0.5)))

    def query(self, q: str, k: int = 4) -> list[dict[str, Any]]:
        q_terms = tokenize(q)
        scored: list[tuple[float, int]] = []
        for i, toks in enumerate(self._tokenized):
            if not toks:
                continue
            tf = Counter(toks)
            dl = len(toks)
            score = 0.0
            for term in q_terms:
                if term not in tf:
                    continue
                idf = self._idf(term)
                freq = tf[term]
                denom = freq + self.k1 * (1 - self.b + self.b * dl / (self._avg_len or 1))
                score += idf * (freq * (self.k1 + 1)) / denom
            if score > 0:
                scored.append((score, i))
        scored.sort(reverse=True)
        results = []
        for score, i in scored[:k]:
            d = dict(self.docs[i])
            d["score"] = round(score, 3)
            results.append(d)
        return results

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.docs)
