"""Multi-agent collaboration engine — two frontier models debate findings.

ARGUS Collaboration Mode pairs two LLMs in alternating turns:
  Agent A (Primary) — hunts, uses tools, finds bugs, proposes hypotheses
  Agent B (Critic) — reviews, challenges assumptions, finds gaps, suggests improvements

Each agent sees the full conversation history including tool calls/results from
the other agent. The conversation streams live to the web UI via SSE callbacks.
Max rounds cap prevents runaway token burn.

Design:
  - Each agent has its own backend (any provider ARGUS supports)
  - Agents can call tools during their turns (tool calls are shared with the other agent)
  - The user can inject messages to steer at any point
  - All state is serializable (save/restore sessions)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import config
from .llm import BackendError, make_backend
from .prompts import build_system_prompt, SYSTEM_DOCTRINE, TRIAGE_DOCTRINE
from .rag import BM25Index
from .tools import build_tools

CRITIC_DOCTRINE = """You are ARGUS-CRITIC, a senior vulnerability researcher acting as a \
skeptical, adversarial reviewer. Your job is to rigorously challenge another agent's findings.

# Your role
- Review the primary agent's analysis with maximum skepticism.
- Identify: unproven assumptions, missing evidence, overclaimed impacts, logical gaps, \
methodology errors, missed attack surface, and things the agent should have checked but didn't.
- Ask specific, pointed questions that force the primary agent to provide concrete evidence.
- If the primary agent claims a bug exists, demand the EXACT code location, the EXACT PoC step, \
and the EXACT impact chain. Vague answers are not acceptable.
- Suggest alternative approaches or additional recon the primary agent should run.

# Tone
Blunt, direct, adversarial. If something is wrong or weak, say so plainly. You are not \
here to be polite — you are here to prevent false positives and missed bugs from reaching Muhammed.

# Rules
- You may call tools (same set as the primary agent) to independently verify claims.
- Always state clearly whether the primary agent's current claim is CONFIRMED, NEEDS MORE \
WORK, or DEBUNKED based on the evidence presented so far.
- When you agree with the primary agent, say so explicitly and state what evidence convinced you.
- The goal is consensus on one of: a confirmed, reproducible finding OR a clean negative result."""


COLLAB_SESSION_DIR = config.ROOT / "runs" / "collab"
COLLAB_SESSION_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MAX_ROUNDS = 8


@dataclass
class TurnResult:
    agent_name: str
    role: str  # "primary" or "critic"
    text: str
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    verdict: str = ""  # CONFIRMED / NEEDS_MORE_WORK / DEBUNKED (critic only)


class Collaboration:
    """Two-agent debate session.

    Usage:
        collab = Collaboration(
            agent_a_cfg=dict(provider="anthropic", model="claude-sonnet-5"),
            agent_b_cfg=dict(provider="deepseek", model="deepseek-chat"),
        )
        collab.start("Audit mydriver.sys for LPE", on_event=emit)
        result = collab.final_consensus()
    """

    def __init__(
        self,
        agent_a_cfg: dict | None = None,
        agent_b_cfg: dict | None = None,
        name_a: str = "Claude (Primary)",
        name_b: str = "DeepSeek (Critic)",
    ):
        # Resolve agent configs — default to configured provider for A,
        # and a secondary provider for B if specified, else same as A.
        main_cfg = config.resolve_llm()

        self.agent_a_cfg = agent_a_cfg or dict(main_cfg)
        self.agent_b_cfg = agent_b_cfg or dict(main_cfg)  # same provider by default

        self.name_a = name_a
        self.name_b = name_b

        self.backend_a = make_backend(self.agent_a_cfg)
        self.backend_b = make_backend(self.agent_b_cfg)

        # Shared tool set (both agents get the same tools)
        self._index = BM25Index.from_corpus(config.CORPUS_FILE)
        self._tool_schemas, self._dispatch = build_tools(self._index)

        # Conversation state
        self.task: str = ""
        self.turns: list[TurnResult] = []
        self.max_rounds: int = DEFAULT_MAX_ROUNDS
        self._round: int = 0
        self._consensus: str = ""
        self._on_event: Callable | None = None

    # --- public API ---------------------------------------------------------

    def start(
        self,
        task: str,
        max_rounds: int = DEFAULT_MAX_ROUNDS,
        on_event: Callable[[dict], None] | None = None,
    ) -> str:
        """Run the full debate loop and return the consensus."""
        self.task = task
        self.max_rounds = max_rounds
        self._on_event = on_event
        self.turns = []
        self._round = 0
        self._consensus = ""

        self._emit("collab_start", task=task, agent_a=self.name_a, agent_b=self.name_b,
                   model_a=self.backend_a.model, model_b=self.backend_b.model)

        # Round 1: Agent A takes the first shot
        self._run_primary_turn()

        # Alternating rounds
        for r in range(2, max_rounds + 1):
            self._round = r
            if self._consensus:
                break
            if r % 2 == 0:
                self._run_critic_turn()
            else:
                self._run_primary_turn()

        if not self._consensus:
            self._consensus = self._final_synthesis()

        self._emit("collab_end", consensus=self._consensus, turns=len(self.turns))
        self._save_session()
        return self._consensus

    def inject_user_message(self, message: str) -> None:
        """Inject Muhammed's message into the conversation for the next turn."""
        self.turns.append(TurnResult(
            agent_name="Muhammed (You)", role="user",
            text=message, verdict="",
        ))
        self._emit("user_msg", text=message)

    def final_consensus(self) -> str:
        return self._consensus or "No consensus reached."

    # --- internal: agent turns ----------------------------------------------

    def _build_conversation_history(self, role: str) -> list[dict]:
        """Build the LLM history from all previous turns.

        Each previous turn is shown as a user message identifying the other agent.
        The task is the first message.
        """
        history: list[dict] = []

        # First message: the task + role instructions
        if role == "primary":
            task_msg = (
                f"# COLLABORATION MODE\n\n"
                f"You are the PRIMARY researcher. You are collaborating with {self.name_b} "
                f"who acts as a skeptical critic reviewing your work.\n\n"
                f"## Task\n{self.task}\n\n"
                f"Proceed with your analysis. Use tools as needed. After presenting your "
                f"findings, your critic will challenge them — be prepared to defend with "
                f"concrete evidence or concede where appropriate.\n\n"
                f"If you reach a point where you believe a finding is CONFIRMED beyond "
                f"reasonable doubt, state so explicitly."
            )
        else:
            task_msg = (
                f"# COLLABORATION MODE\n\n"
                f"You are the CRITIC. You are reviewing the work of {self.name_a} "
                f"who is the primary researcher.\n\n"
                f"## Original Task\n{self.task}\n\n"
                f"Review the primary agent's analysis below. Challenge every assumption, "
                f"demand evidence for every claim, point out gaps, and suggest what else "
                f"should be checked. Use tools if you need to independently verify something.\n\n"
                f"Rate each finding: CONFIRMED / NEEDS MORE WORK / DEBUNKED."
            )

        history.append({"role": "user", "text": task_msg})

        # Previous turns as alternating messages
        for turn in self.turns:
            label = f"### {turn.agent_name} [{turn.role}]"
            if turn.verdict:
                label += f" — VERDICT: {turn.verdict}"

            body = f"{label}\n\n{turn.text}"
            if turn.tool_calls:
                body += f"\n\nTool calls made ({len(turn.tool_calls)}):\n"
                for tc in turn.tool_calls:
                    body += f"  - {tc['name']}({json.dumps(tc['input'])[:200]})\n"
            if turn.tool_results:
                body += f"\n\nTool results ({len(turn.tool_results)}):\n"
                for tr in turn.tool_results:
                    body += f"  [{tr['name']}] {tr['output'][:500]}\n"

            history.append({"role": "user", "text": body})

        return history

    def _run_primary_turn(self) -> None:
        self._emit("turn_start", agent=self.name_a, role="primary", round=self._round)

        history = self._build_conversation_history("primary")
        system = build_system_prompt(mode="hunt") + (
            "\n\n# COLLABORATION PROTOCOL\n"
            f"You are collaborating with {self.name_b} (critic). After presenting your "
            "analysis, be prepared for adversarial review. State clearly what is CONFIRMED "
            "vs what is HYPOTHESIS. When your critic points out gaps, address them with "
            "specific evidence — do not hand-wave."
        )

        turn = self._run_agent_turn(
            backend=self.backend_a,
            name=self.name_a,
            role="primary",
            system=system,
            history=history,
        )
        self.turns.append(turn)

    def _run_critic_turn(self) -> None:
        self._emit("turn_start", agent=self.name_b, role="critic", round=self._round)

        history = self._build_conversation_history("critic")
        system = CRITIC_DOCTRINE + (
            f"\n\nYou are reviewing {self.name_a}'s work on: {self.task}"
        )

        turn = self._run_agent_turn(
            backend=self.backend_b,
            name=self.name_b,
            role="critic",
            system=system,
            history=history,
        )
        self.turns.append(turn)

        # Wire critic verdict into progression (XP/ledger)
        if turn.verdict and turn.verdict != "ERROR":
            try:
                from . import progression
                finding = {
                    "title": self.task[:120],
                    "target": turn.agent_name,
                    "cwe": "",
                    "summary": turn.text[:500],
                }
                prog = progression.award_from_verdict(finding, turn.verdict)
                if not prog.get("skipped"):
                    self._emit("progression", verdict=turn.verdict,
                               xp=prog.get("xp_gained", 0),
                               level=prog.get("level", 1),
                               rank=prog.get("rank", "?"))
            except Exception:
                pass  # progression is optional

        # Check for consensus
        text_lower = turn.text.lower()
        if "confirmed" in text_lower and "debunked" not in text_lower:
            has_agreement = any(
                "confirmed" in self.turns[-2].text.lower()
                for _ in [1] if len(self.turns) >= 2
            )
            if has_agreement:
                self._consensus = f"CONSENSUS: Both agents agree.\n\n{self.turns[-1].text}\n\n{self.turns[-2].text[:500]}"

    def _run_agent_turn(
        self, backend, name: str, role: str, system: str, history: list[dict]
    ) -> TurnResult:
        max_steps_per_turn = 8
        tool_calls_all: list[dict] = []
        tool_results_all: list[dict] = []
        final_text = ""
        verdict = ""

        for step in range(1, max_steps_per_turn + 1):
            try:
                resp = backend.converse(system, history, self._tool_schemas)
            except BackendError as e:
                self._emit("turn_error", agent=name, error=str(e))
                return TurnResult(
                    agent_name=name, role=role,
                    text=f"[ERROR: {e}]", verdict="ERROR"
                )

            history.append({
                "role": "assistant", "text": resp["text"],
                "tool_calls": resp.get("tool_calls", []),
            })

            if resp.get("text"):
                final_text = resp["text"]
                self._emit("turn_text", agent=name, role=role, text=resp["text"][:3000])

            if resp.get("stop") or not resp.get("tool_calls"):
                break

            results = []
            for tc in resp.get("tool_calls", []):
                self._emit("tool_call", agent=name, name=tc["name"], input=tc["input"])
                out = self._run_tool(tc["name"], tc["input"])
                tool_calls_all.append(tc)
                tool_results_all.append({"name": tc["name"], "output": out})
                results.append({"id": tc.get("id", ""), "name": tc["name"], "output": out})
                self._emit("tool_result", agent=name, name=tc["name"], output=out[:500])

            history.append({"role": "tool", "results": results})

        # Extract verdict if critic
        if role == "critic":
            tl = final_text.upper()
            for v in ["CONFIRMED", "DEBUNKED", "NEEDS MORE WORK"]:
                if v in tl:
                    verdict = v.title() if v != "NEEDS MORE WORK" else "Needs More Work"
                    break

        return TurnResult(
            agent_name=name, role=role, text=final_text,
            tool_calls=tool_calls_all, tool_results=tool_results_all,
            verdict=verdict,
        )

    def _run_tool(self, name: str, tool_input: dict) -> str:
        handler = self._dispatch.get(name)
        if handler is None:
            return f"ERROR: unknown tool {name!r}"
        try:
            return handler(tool_input)
        except Exception as e:
            return f"ERROR: tool {name} raised {type(e).__name__}: {e}"

    def _final_synthesis(self) -> str:
        """Ask Agent A for a final summary synthesizing both agents' contributions."""
        prompt = (
            f"# FINAL SYNTHESIS\n\n"
            f"Original task: {self.task}\n\n"
            f"Below is the full collaboration transcript. {self.name_a} and {self.name_b} "
            f"debated the findings but did not reach explicit consensus. Please provide:\n\n"
            f"1. What was CONFIRMED with high confidence\n"
            f"2. What needs MORE WORK (specific next steps)\n"
            f"3. What was DEBUNKED (and should be parked)\n\n"
            f"{'='*60}\n\n"
        )
        for t in self.turns:
            prompt += f"### {t.agent_name} [{t.role}]\n{t.text[:1000]}\n\n"

        try:
            synth = self.backend_a.complete(prompt)
        except Exception:
            synth = "(synthesis unavailable)"
        return synth

    # --- persistence --------------------------------------------------------

    def _save_session(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = COLLAB_SESSION_DIR / f"collab-{stamp}.json"
        data = {
            "task": self.task,
            "agent_a": self.name_a, "agent_b": self.name_b,
            "model_a": self.backend_a.model, "model_b": self.backend_b.model,
            "turns": len(self.turns), "consensus": self._consensus,
            "transcript": [
                {
                    "agent": t.agent_name, "role": t.role, "text": t.text,
                    "verdict": t.verdict,
                    "tool_calls": len(t.tool_calls), "tool_results": len(t.tool_results),
                }
                for t in self.turns
            ],
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _emit(self, kind: str, **data) -> None:
        if self._on_event:
            try:
                self._on_event({"type": kind, **data})
            except Exception:
                pass

    def to_dict(self) -> dict:
        return {
            "task": self.task,
            "agent_a": self.name_a, "agent_b": self.name_b,
            "model_a": self.backend_a.model, "model_b": self.backend_b.model,
            "turns": [
                {
                    "agent": t.agent_name, "role": t.role, "text": t.text,
                    "verdict": t.verdict,
                    "tool_calls": [{"name": tc["name"], "input": tc["input"]} for tc in t.tool_calls],
                    "tool_results": [{"name": tr["name"], "output": tr["output"][:300]} for tr in t.tool_results],
                }
                for t in self.turns
            ],
            "consensus": self._consensus,
            "max_rounds": self.max_rounds,
        }
