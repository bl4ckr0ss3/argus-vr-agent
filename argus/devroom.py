"""Live development room — OpenCode and Opus 5 chat in real time.

Both agents watch a shared file (DEV_ROOM.md). When one agent detects a new
message addressed to it (@opencode / @opus5 / @all), it formulates a response,
appends it to the room, and the other agent sees it on its next poll cycle.

Run in each agent's session:
    python run.py devroom --agent opencode
    python run.py devroom --agent opus5

The user types directly into DEV_ROOM.md or uses the web panel. Both agents
see the message and respond simultaneously.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import config

ROOM_FILE = config.ROOT / "DEV_ROOM.md"
STATE_FILE = config.ROOT / "runs" / "devroom_state.json"
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

_TS = lambda: datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

AGENT_COLORS = {
    "opencode": "🟢",
    "opus5": "🔵",
    "muhammed": "🟡",
}

SYSTEM_MSG_HEADER = """# ARGUS Development Room

Live chat between OpenCode (DeepSeek V4 Pro) and Claude Opus 5.
Both agents watch this file. Type below to talk to both simultaneously.

- Direct messages: start a line with `@opencode`, `@opus5`, or `@all`
- Agents auto-respond when they detect messages addressed to them
- This file is the source of truth — agents poll it, not each other

---

"""


def init_room() -> None:
    if not ROOM_FILE.exists() or ROOM_FILE.stat().st_size < 10:
        ROOM_FILE.write_text(SYSTEM_MSG_HEADER, encoding="utf-8")


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"last_line": 0, "last_hash": ""}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def read_messages() -> tuple[list[dict], int]:
    """Read all messages from the room file. Returns (messages, line_count)."""
    if not ROOM_FILE.exists():
        return [], 0
    lines = ROOM_FILE.read_text(encoding="utf-8").splitlines()
    msgs = []
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith("### [") and "]" in line:
            # Parse message header: ### [12:34:56 UTC] AgentName
            rest = line[4:]
            if rest.startswith("[") and "]" in rest:
                end = rest.index("]")
                ts = rest[1:end]
                agent = rest[end + 1:].strip()
                # Collect the body until next header or end
                body_lines = []
                for j in range(i + 1, len(lines)):
                    if lines[j].strip().startswith("### ["):
                        break
                    body_lines.append(lines[j])
                body = "\n".join(body_lines).strip()
                msgs.append({
                    "line": i, "timestamp": ts, "agent": agent,
                    "text": body, "raw_line": line,
                })
    return msgs, len(lines)


def find_new_messages(old_msgs: list[dict], new_msgs: list[dict]) -> list[dict]:
    """Return messages that appeared after the last known message."""
    if not old_msgs:
        return new_msgs
    old_texts = {m["raw_line"] for m in old_msgs}
    return [m for m in new_msgs if m["raw_line"] not in old_texts]


def is_addressed_to(msg: dict, agent_name: str) -> bool:
    """Does this message target our agent?"""
    text = msg["text"].lower()
    raw = msg["raw_line"].lower()

    # Direct mentions
    if f"@{agent_name}" in text:
        return True
    if "@all" in text:
        return True
    if "@both" in text:
        return True

    # Questions / interaction patterns
    agent = msg["agent"].lower().strip()
    if agent != agent_name:
        # Message from the OTHER agent — might be a handoff or reply to us
        if any(phrase in text for phrase in [
            "opencode", "open code", "open-code", "deepseek", "v4 pro",
        ]) and agent_name == "opencode":
            return True
        if any(phrase in text for phrase in [
            "opus", "claude", "opus5", "opus 5",
        ]) and agent_name == "opus5":
            return True

    # The other agent asking a question
    if "?" in text and agent != agent_name:
        # If the other agent asked something, and it's not a reply to us specifically
        if agent_name == "opencode" and "opencode" not in text.lower():
            return False
        if agent_name == "opus5" and "opus" not in text.lower():
            return False
        return True

    return False


def build_response(agent_name: str, msg: dict, previous_msgs: list[dict]) -> str:
    """Compose a reply from this agent to the given message."""
    # We use the LLM backend to craft a proper response
    from .llm import make_backend

    context = "\n".join(
        f"[{m['agent']}]: {m['text'][:300]}"
        for m in previous_msgs[-5:]
    )

    prompt = (
        f"You are {agent_name.upper()} in the ARGUS development room. "
        f"Another agent just wrote:\n\n"
        f"### [{msg['agent']}]: {msg['text']}\n\n"
        f"Recent chat context:\n{context}\n\n"
        f"Reply naturally as {agent_name}. Be concise. If they asked a question, "
        f"answer it. If they made a claim about code you own, confirm or push back. "
        f"If it's a handoff, acknowledge and act. "
        f"Reply with ONLY the message body — no headers or formatting.\n\n"
        f"Your reply:"
    )

    backend = make_backend()
    try:
        reply = backend.complete(prompt)
    except Exception as e:
        reply = f"(could not generate reply: {e})"

    return reply.strip()


def append_message(agent_name: str, text: str) -> None:
    """Append a message to the room file."""
    icon = AGENT_COLORS.get(agent_name.lower(), "⚪")
    header = f"\n### [{_TS()}] {icon} {agent_name}\n"
    body = text.strip()
    with ROOM_FILE.open("a", encoding="utf-8") as f:
        f.write(header + body + "\n")


def watch(agent_name: str, interval: float = 3.0, once: bool = False):
    """Main watch loop. Polls DEV_ROOM.md, detects new messages, responds."""
    init_room()

    icon = AGENT_COLORS.get(agent_name.lower(), "⚪")
    print(f"{icon} [{agent_name}] Watching DEV_ROOM.md (polling every {interval}s)")

    # Send a join message
    append_message(agent_name, f"Joined the room. Ready to collaborate.")

    last_msgs: list[dict] = []

    try:
        while True:
            msgs, _ = read_messages()
            new = find_new_messages(last_msgs, msgs)

            for msg in new:
                if msg["agent"].lower().strip() == agent_name.lower():
                    continue  # skip our own messages

                if is_addressed_to(msg, agent_name):
                    print(f"\n{icon} [{agent_name}] New message from {msg['agent']}:")
                    print(f"   {msg['text'][:200]}...")
                    print(f"   ↳ Crafting response...")

                    try:
                        reply = build_response(agent_name, msg, msgs[:msgs.index(msg)])
                        if reply:
                            append_message(agent_name, reply)
                            print(f"   ↳ Replied ({len(reply)} chars)")
                        else:
                            print(f"   ↳ No reply generated")
                    except Exception as e:
                        print(f"   ↳ Error: {e}")

            last_msgs = msgs

            if once:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        append_message(agent_name, f"Left the room.")
        print(f"\n{icon} [{agent_name}] Disconnected.")


def list_room() -> str:
    """Print the current room transcript."""
    if not ROOM_FILE.exists():
        return "(room is empty)"
    return ROOM_FILE.read_text(encoding="utf-8")
