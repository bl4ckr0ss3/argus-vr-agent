"""Score ARGUS against the vault-derived benchmark.

Two metrics per question:
  - keyword coverage: fraction of `must_include` terms present in the answer
    (cheap, deterministic, no extra API cost).
  - judge score (optional, --judge): Claude grades the answer against the
    reference on a 0-2 scale (0 wrong, 1 partial, 2 correct).

This is how you tell whether a change (new exemplars, prompt tweak, model swap)
actually made the agent better rather than just different.

    python eval/evaluate.py            # keyword metric only
    python eval/evaluate.py --judge    # + LLM-judged correctness
    python eval/evaluate.py --dry      # print the benchmark, no API calls
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import config  # noqa: E402


def load_benchmark() -> list[dict]:
    if not config.BENCHMARK_FILE.exists():
        raise FileNotFoundError("benchmark missing — run `python run.py index` first.")
    items = []
    with config.BENCHMARK_FILE.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def keyword_score(answer: str, must_include: list[str]) -> float:
    if not must_include:
        return 1.0
    a = answer.lower()
    hits = sum(1 for kw in must_include if kw.lower() in a)
    return hits / len(must_include)


def judge(agent, question: str, reference: str, answer: str) -> int:
    prompt = (
        "You are grading a vulnerability-research answer against a reference.\n"
        f"QUESTION:\n{question}\n\nREFERENCE (correct):\n{reference}\n\n"
        f"CANDIDATE ANSWER:\n{answer}\n\n"
        "Score the candidate's technical correctness: 0 = wrong/misleading, "
        "1 = partially correct or incomplete, 2 = fully correct. "
        "Reply with ONLY the single digit."
    )
    txt = agent.complete(prompt).strip()
    for ch in txt:
        if ch in "012":
            return int(ch)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true", help="also grade with an LLM judge")
    ap.add_argument("--dry", action="store_true", help="print benchmark without calling the API")
    ap.add_argument("--max-steps", type=int, default=10)
    args = ap.parse_args()

    bench = load_benchmark()
    if args.dry:
        for it in bench:
            print(f"[{it['id']}] target={it.get('target')}")
            print(f"  Q: {it['question']}")
            print(f"  must_include: {it.get('must_include')}")
        print(f"\n{len(bench)} benchmark items.")
        return

    # load .env into os.environ (stdlib)
    import os
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    from argus.agent import Argus
    agent = Argus(verbose=False)

    kw_total = 0.0
    judge_total = 0
    rows = []
    for it in bench:
        result = agent.run(it["question"], max_steps=args.max_steps)
        ans = result.final_text
        kw = keyword_score(ans, it.get("must_include", []))
        kw_total += kw
        j = None
        if args.judge:
            j = judge(agent, it["question"], it["reference"], ans)
            judge_total += j
        rows.append((it["id"], kw, j))
        print(f"[{it['id']}] keyword={kw:.2f}" + (f" judge={j}/2" if j is not None else ""))

    n = len(bench)
    print("\n" + "=" * 50)
    print(f"Keyword coverage: {kw_total / n:.1%}  ({n} items)")
    if args.judge:
        print(f"Judge score:      {judge_total}/{2 * n}  ({judge_total / (2 * n):.1%})")


if __name__ == "__main__":
    main()
