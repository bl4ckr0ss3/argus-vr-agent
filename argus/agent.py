"""ARGUS agent core — provider-agnostic tool-use loop.

Runs one agentic loop over a provider-neutral message history (see argus/llm.py).
Works identically on DeepSeek, OpenAI, a local model, or Anthropic. A hard step
cap bounds every run so it can never spin unattended.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import config
from .llm import BackendError, make_backend
from .prompts import build_system_prompt
from .rag import BM25Index
from .tools import build_tools


@dataclass
class HuntResult:
    final_text: str
    steps: int
    stopped_reason: str
    transcript: list[dict] = field(default_factory=list)


class Argus:
    def __init__(self, model: str | None = None, verbose: bool = True, mode: str = "hunt"):
        self.backend = make_backend()
        if model:
            self.backend.model = model
        self.model = self.backend.model
        self.provider = self.backend.provider
        self.verbose = verbose
        self.mode = mode
        self.index = BM25Index.from_corpus(config.CORPUS_FILE)
        self.tool_schemas, self.dispatch = build_tools(self.index)
        self.system = build_system_prompt(mode=mode)

    @property
    def ready(self) -> bool:
        return self.backend.ready

    # --- tool execution ----------------------------------------------------
    def _run_tool(self, name: str, tool_input: dict) -> str:
        handler = self.dispatch.get(name)
        if handler is None:
            return f"ERROR: unknown tool {name!r}"
        try:
            return handler(tool_input)
        except Exception as e:  # never let a tool crash the loop
            return f"ERROR: tool {name} raised {type(e).__name__}: {e}"

    def _log(self, *a) -> None:
        if self.verbose:
            print(*a, flush=True)

    # --- context control ---------------------------------------------------
    def _trim_history(self, history: list[dict]) -> None:
        """Bound context growth on long hunts: keep the task + the most recent
        HISTORY_KEEP_RECENT entries verbatim, and truncate OLDER tool outputs.
        Mutates in place. tool_use/tool_result pairing is preserved (we only
        shorten the output string), so the model never sees a malformed history.
        """
        keep = config.HISTORY_KEEP_RECENT
        cap = config.HISTORY_OLD_TOOL_CAP
        if len(history) <= keep + 1:
            return
        protected_start = len(history) - keep
        for i in range(1, protected_start):  # skip task at [0] and the recent tail
            h = history[i]
            if h.get("role") != "tool":
                continue
            for r in h.get("results", []):
                out = r.get("output", "")
                if len(out) > cap:
                    r["output"] = out[:cap] + f"\n[… trimmed {len(out) - cap} chars of older tool output …]"

    # --- main loop ---------------------------------------------------------
    def run(
        self,
        task: str,
        max_steps: int | None = None,
        on_event: Callable[[dict], None] | None = None,
    ) -> HuntResult:
        def emit(kind: str, **data) -> None:
            if on_event is not None:
                try:
                    on_event({"type": kind, **data})
                except Exception:
                    # A broken event sink (e.g. a disconnected web-console SSE
                    # client) must never take the hunt down with it.
                    pass

        if not self.backend.ready:
            msg = f"LLM backend not ready ({self.provider}): {self.backend.error}"
            emit("error", message=msg)
            return HuntResult(final_text=msg, steps=0, stopped_reason="error", transcript=[])

        max_steps = max_steps or config.MAX_STEPS
        history: list[dict] = [{"role": "user", "text": task}]
        transcript: list[dict] = []
        final_text = ""
        stopped = "completed"
        step = 0

        for step in range(1, max_steps + 1):
            emit("step", step=step, max_steps=max_steps)
            self._trim_history(history)  # bound context so deep hunts don't overflow
            try:
                resp = self.backend.converse(self.system, history, self.tool_schemas)
            except BackendError as e:
                emit("error", message=str(e))
                return HuntResult(final_text=str(e), steps=step, stopped_reason="error", transcript=transcript)

            history.append({"role": "assistant", "text": resp["text"], "tool_calls": resp["tool_calls"]})
            if resp["text"]:
                final_text = resp["text"]
                self._log(f"\n=== step {step} · reasoning ===\n{resp['text']}")
                emit("reasoning", step=step, text=resp["text"])

            if resp["stop"] or not resp["tool_calls"]:
                stopped = "completed"
                break

            results = []
            for tc in resp["tool_calls"]:
                self._log(f"  -> {tc['name']}({json.dumps(tc['input'])[:200]})")
                emit("tool_call", step=step, name=tc["name"], input=tc["input"])
                out = self._run_tool(tc["name"], tc["input"])
                transcript.append({"tool": tc["name"], "input": tc["input"], "output": out})
                self._log(f"     {out[:300].replace(chr(10), ' ')}")
                emit("tool_result", step=step, name=tc["name"], output=out)
                results.append({"id": tc["id"], "name": tc["name"], "output": out})
            history.append({"role": "tool", "results": results})
        else:
            stopped = "max_steps"

        emit("final", text=final_text, steps=step, stopped_reason=stopped)
        return HuntResult(final_text=final_text, steps=step, stopped_reason=stopped, transcript=transcript)

    # --- convenience -------------------------------------------------------
    def complete(self, prompt: str) -> str:
        return self.backend.complete(prompt)

    def save_run(self, task: str, result: HuntResult) -> Path:
        config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = config.RUNS_DIR / f"hunt-{stamp}.json"
        path.write_text(json.dumps({
            "task": task,
            "provider": self.provider,
            "model": self.model,
            "steps": result.steps,
            "stopped_reason": result.stopped_reason,
            "final_text": result.final_text,
            "transcript": result.transcript,
        }, indent=2), encoding="utf-8")
        return path
