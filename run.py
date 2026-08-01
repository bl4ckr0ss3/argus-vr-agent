#!/usr/bin/env python
"""ARGUS command-line entrypoint.

    python run.py index                 # (re)build the dataset from the vault
    python run.py retrieve "<query>"    # test RAG retrieval only (no API key needed)
    python run.py ask "<question>"      # short Q&A run (few tool steps)
    python run.py hunt "<target/task>"  # full hunt, transcript saved to runs/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Load .env BEFORE importing config so API keys are available at module load time.
import os
_env = ROOT / ".env"
if _env.exists():
    for _line in _env.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

import config  # noqa: E402


def _try_dotenv() -> None:
    """Load .env into os.environ (stdlib; no python-dotenv needed)."""
    import os
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def cmd_index(_args) -> None:
    from dataset import build_dataset
    build_dataset.main()


def cmd_retrieve(args) -> None:
    from argus.rag import BM25Index
    idx = BM25Index.from_corpus(config.CORPUS_FILE)
    print(f"(corpus: {len(idx)} chunks)\n")
    for h in idx.query(args.query, k=args.k):
        meta = h.get("meta", {})
        print(f"[score {h['score']}] {meta.get('source')} · target={meta.get('target')}")
        print(h["text"][:500])
        print("-" * 70)


def _run_agent(task: str, max_steps: int, mode: str = "hunt") -> None:
    _try_dotenv()
    from argus.agent import Argus
    agent = Argus(mode=mode)
    print(f"ARGUS ({agent.model}, mode={mode}) — running (max {max_steps} steps)\n")
    result = agent.run(task, max_steps=max_steps)
    print("\n" + "=" * 70)
    print(f"FINAL ({result.stopped_reason}, {result.steps} steps):\n")
    print(result.final_text)
    path = agent.save_run(task, result)
    print(f"\n[transcript saved -> {path}]")


def cmd_ask(args) -> None:
    _run_agent(args.question, max_steps=args.max_steps or 12)


def cmd_web(args) -> None:
    from web.server import serve
    serve(host=args.host, port=args.port)


def cmd_app(_args) -> None:
    from argus_app import main as app_main
    app_main()


def cmd_fetch(args) -> None:
    _try_dotenv()
    from argus.intel import malwarebazaar
    print(f"Fetching up to {args.limit} sample(s) from MalwareBazaar into {config.INTAKE_DIR} …")
    print("!!! This downloads LIVE malware — you should be inside an isolated VM. !!!")
    written = malwarebazaar.fetch_to_intake(limit=args.limit, tag=args.tag)
    print(f"{len(written)} new sample(s) written. Run `python run.py watch --once` to triage them.")


def cmd_watch(args) -> None:
    _try_dotenv()
    from argus.intel import watcher
    watcher.watch(interval=args.interval, llm=args.llm, once=args.once)


def cmd_triage(args) -> None:
    task = (
        f"A suspicious sample is at: {args.sample}\n\n"
        "Perform static malware triage. Unpack it if it is an archive, run "
        "triage_report on the extracted files, and produce an analyst triage "
        "summary with a verdict, capability hypotheses, and a deduplicated IOC table. "
        "Do NOT execute the sample."
    )
    _run_agent(task, max_steps=args.max_steps or 20, mode="triage")


def cmd_detonate(args) -> None:
    """Direct dynamic analysis — no LLM, just the tool. Streams each stage live."""
    _try_dotenv()
    from argus.tools.dynamic import run_detonation
    run_detonation(args.sample, args.timeout,
                   on_progress=lambda line: print(line, flush=True))


def cmd_reanalyze(args) -> None:
    """Re-run auto-analysis on an existing detonation folder (no re-detonation)."""
    _try_dotenv()
    from argus.tools.dynamic import reanalyze_run
    reanalyze_run(args.run, on_progress=lambda line: print(line, flush=True))


def cmd_hunt(args) -> None:
    task = (
        f"Begin a vulnerability-research hunt on the following target/task:\n\n{args.task}\n\n"
        "Follow the operating procedure: orient via retrieve_knowledge, recon the "
        "attack surface, form and log hypotheses with record_candidate, and verify "
        "against the four gates. End with a prioritized candidate list and the single "
        "next experiment for each."
    )
    _run_agent(task, max_steps=args.max_steps or config.MAX_STEPS)


def cmd_collab(args) -> None:
    _try_dotenv()
    from argus.collab import Collaboration

    # Provider-aware default models for the two debaters. If the resolved
    # model is a GLM-5.x (either direct Zhipu provider, agentrouter, or
    # OpenRouter) pair the flagship 5.2 as primary with 5.1 as the
    # skeptical critic so the two can research together. Other providers
    # fall back to their own preset model for both seats.
    resolved = config.resolve_llm()
    default_primary = resolved["model"]
    default_critic = resolved["model"]
    model_lc = resolved["model"].lower()
    if resolved["provider"] in ("glm", "agentrouter") or "glm-5" in model_lc:
        if resolved["provider"] in ("openrouter", "agentrouter"):
            default_primary = "z-ai/glm-5.2"
            default_critic = "z-ai/glm-5.1"
        else:
            default_primary = "glm-5.2"
            default_critic = "glm-5.1"
    elif resolved["provider"] == "openrouter":
        default_primary = "deepseek/deepseek-v4-pro"
        default_critic = "deepseek/deepseek-v4-pro"

    collab = Collaboration(
        name_a=f"{resolved['provider']} ({default_primary} · Primary)",
        name_b=f"{resolved['provider']} ({default_critic} · Critic)",
    )
    # Override models from CLI args (None -> provider-aware default above)
    collab.agent_a_cfg["model"] = args.agent_a or default_primary
    collab.agent_b_cfg["model"] = args.agent_b or default_critic

    print(f"ARGUS COLLABORATION — {collab.name_a}  vs  {collab.name_b}")
    print(f"Task: {args.task}\n")

    def emit(ev):
        if ev["type"] == "turn_start":
            print(f"\n{'='*60}\n[{ev['agent']}] ({ev['role']})")
        elif ev["type"] == "turn_text":
            print(ev["text"][:3000])
        elif ev["type"] == "tool_call":
            print(f"  -> {ev['name']}({json.dumps(ev['input'])[:120]})")
        elif ev["type"] == "tool_result":
            print(f"  <- {ev['name']}: {ev['output'][:300]}")
        elif ev["type"] == "progression":
            print(f"  [XP +{ev.get('xp',0)} · L{ev.get('level',1)} {ev.get('rank','?')} · {ev.get('verdict','')}]")
        elif ev["type"] == "collab_end":
            print(f"\n{'='*60}\nCONSENSUS:\n{ev['consensus']}")

    consensus = collab.start(args.task, max_rounds=args.rounds, on_event=emit)
    print(f"\n{'='*60}\n[debate complete · {consensus[:500]}...]" if len(consensus) > 500 else f"\n{'='*60}\n[debate complete · {consensus}]")


def cmd_workflow(args) -> None:
    _try_dotenv()
    from argus.workflow import WorkflowEngine, seed_tasks

    if args.seed:
        n = seed_tasks()
        print(f"Seeded {n} initial tasks.")
        if args.once:
            return

    engine = WorkflowEngine(args.agent)
    engine.loop(once=args.once, interval=max(5, args.interval))


def cmd_netplan(args) -> None:
    from argus.intel import sinkhole
    out = args.out or str(Path(args.report).expanduser().parent / "netplan")
    sinkhole.main([args.report, "--out", out])


def cmd_diff(args) -> None:
    from argus.intel import rundiff
    argv = [args.run_a, args.run_b]
    if args.out:
        argv += ["--out", args.out]
    rundiff.main(argv)


def cmd_memscan(args) -> None:
    """Volatility3 cross-view memory forensics for hidden processes/drivers."""
    _try_dotenv()
    from argus import memscan

    if args.acquire:
        r = memscan.acquire(args.acquire)
        print(r.get("error") or f"dumped -> {r['path']} ({r['size_mb']} MB) — now: python run.py memscan {r['path']}")
        return
    if not args.dump:
        print("Point it at a memory dump:  python run.py memscan <dump.raw>")
        print("  (a suspended VMware VM's .vmem works, or:  python run.py memscan --acquire dump.raw)")
        return

    r = memscan.scan(args.dump)
    if r.get("error"):
        print(r["error"]); return
    print("volatility rows: " + ", ".join(f"{k}={v}" for k, v in r["stats"].items()))
    f = r["findings"]
    if not f:
        print("No hidden processes/drivers or injected code found.")
        print("  (Clean — or the dump/symbols didn't resolve. Check the volatility rows above:")
        print("   all 0/ERR usually means a profile/symbol mismatch, not a clean system.)")
        return
    print(f"\n⚠ {len(f)} MEMORY FINDING(S):")
    for x in f:
        print(f"  [{x['severity']:>8}] {x['what']}: {x['detail']}")
    if any(x["severity"] == "CRITICAL" for x in f):
        print("\n  CRITICAL — hidden kernel object(s). This is a rootkit signature; revert the VM.")


def cmd_bootscan(args) -> None:
    """Boot-chain differential forensics for rootkit/bootkit research."""
    _try_dotenv()
    from argus import bootscan

    if args.baseline:
        r = bootscan.baseline()
        print(f"baseline captured -> {r['path']}")
        print("  " + bootscan.summarize(r["capture"]))
        if not r["capture"]["admin"]:
            print("  ! NOT elevated — MBR/VBR/ESP need Administrator; re-run in an admin shell.")
        print("\nNow: detonate the sample, REBOOT the VM, then: python run.py bootscan --compare")
        return

    if args.compare:
        r = bootscan.compare()
        if r.get("error"):
            print(r["error"]); return
        f = r["findings"]
        if not f:
            print("No boot-chain changes detected.")
            print("  (Clean — or the tamper is below this visibility: consider CHIPSEC for")
            print("   firmware/SPI and Volatility memory forensics for a hidden kernel driver.)")
            return
        print(f"⚠ {len(f)} BOOT-CHAIN FINDING(S):\n")
        for x in f:
            print(f"  [{x['severity']:>8}] {x['what']}: {x['detail']}")
        if any(x["severity"] == "CRITICAL" for x in f):
            print("\n  CRITICAL boot-chain tampering — treat this VM as compromised; revert the snapshot.")
        return

    if args.show:
        from argus import bootscan as bs
        if bs._BASELINE.exists():
            import json as _j
            print("baseline: " + bootscan.summarize(_j.loads(bs._BASELINE.read_text(encoding="utf-8"))))
        else:
            print("no baseline captured yet.")
        return

    print("Use --baseline (before), then --compare (after reboot). --show prints the baseline.")


def cmd_ioc(args) -> None:
    """Extract shareable IOCs from a detonation run."""
    _try_dotenv()
    from argus import ioc
    r = ioc.extract_run(args.run)
    if r.get("error"):
        print(r["error"]); return
    iocs = r["iocs"]
    total = sum(len(v) for v in iocs.values())
    if total == 0:
        print("No IOCs extracted (benign/quiet sample, or procmon wasn't parsed)."); return

    out_dir = Path(args.run)
    csv_text = ioc.to_csv(iocs, do_defang=args.defang)
    (out_dir / "iocs.csv").write_text(csv_text, encoding="utf-8")
    (out_dir / "iocs.json").write_text(json.dumps(iocs, indent=2), encoding="utf-8")

    print(f"{total} IOC(s)" + (" (defanged)" if args.defang else "") + ":")
    for cat, values in iocs.items():
        if values:
            print(f"  {cat} ({len(values)}):")
            for v in values[:12]:
                print(f"    {ioc.defang(v, ioc._KIND.get(cat, cat)) if args.defang else v}")
    print(f"\n  -> {out_dir / 'iocs.csv'}\n  -> {out_dir / 'iocs.json'}")


def cmd_selftest(args) -> None:
    """Validate the pipeline against known-answer samples in a manifest."""
    _try_dotenv()
    from argus import selftest
    r = selftest.run_manifest(args.manifest)
    if r.get("error"):
        print(r["error"])
        print("  Create one from validation/manifest.example.json — see validation/README.md")
        sys.exit(1)
    if not r["cases"]:
        print("manifest has no cases."); return
    for c in r["cases"]:
        mark = {"pass": "PASS", "fail": "FAIL", "error": "ERR "}.get(c["status"], "?")
        print(f"  [{mark}] {c['name']} ({c.get('type', '?')})")
        for reason in c.get("reasons", []):
            print(f"          - {reason}")
    print(f"\n{r['passed']}/{r['total']} passed" + (f", {r['failed']} FAILED" if r["failed"] else ""))
    if r["failed"]:
        sys.exit(1)


def cmd_doctor(_args) -> None:
    """Preflight: is this VM correctly configured, and in which mode?"""
    _try_dotenv()
    from argus import doctor
    r = doctor.assess()
    sym = {"ok": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
    print("ARGUS preflight\n" + "=" * 48)
    for c in r["checks"]:
        print(f"  {sym.get(c['status'], '[ ?? ]')}  {c['name']:<18} {c['detail']}")
    rd = r["readiness"]
    print("=" * 48)
    print(f"  network mode : {rd['mode']}")
    print(f"  DETONATION   : {'READY' if rd['detonation'] else 'NOT READY'} "
          "(needs procmon on PATH + no LLM keys)")
    print(f"  COLLECTION   : {'READY' if rd['collection'] else 'NOT READY'} "
          "(needs internet + MALWAREBAZAAR_API_KEY)")
    if not rd["detonation"] and not rd["collection"]:
        print("\n  Run scripts\\vm-setup.ps1, then snapshot 'clean-baseline'.")


def cmd_rules(args) -> None:
    """Fetch / enable / disable community YARA rulesets."""
    _try_dotenv()
    from argus import rules_fetch

    if args.sources or (not any([args.fetch, args.enable, args.disable, args.all])):
        print("Community YARA sources:\n")
        for s in rules_fetch.list_sources():
            mark = "ON " if s["enabled"] else "off"
            print(f"  [{mark}] {s['name']:<16} {s['fetched']:>4} rules  · {s['repo']}")
            print(f"        {s['desc']}")
        print("\nFetch:   python run.py rules --fetch <name>   (or --all)")
        print("Enable:  python run.py rules --enable <name>  (adds it to scanning)")
        return

    if args.fetch or args.all:
        targets = list(rules_fetch.SOURCES) if args.all else [args.fetch]
        for name in targets:
            print(f"Fetching '{name}' …")
            r = rules_fetch.fetch(name, limit=args.limit)
            if r.get("error"):
                print(f"  ERROR: {r['error']}")
            else:
                print(f"  {r['count']} rule(s) staged -> {r['dir']}  (skipped {r['skipped']})")
        print("\nEnable what you trust:  python run.py rules --enable <name>")
        return

    if args.enable:
        r = rules_fetch.enable(args.enable)
        if r.get("error"):
            print(r["error"]); return
        # advisory compile summary (fast; the engine skips non-compiling rules)
        from argus import rule_quality
        from pathlib import Path as _P
        src_files = sorted((rules_fetch._community_dir() / args.enable).rglob("*.yar"))
        if src_files:
            cs = rule_quality.compile_summary(src_files)
            print(f"enabled '{args.enable}' — now scanned. "
                  f"Compile check: {cs['ok']}/{cs['total']} OK" +
                  (f", {cs['fail']} skipped ({', '.join(cs['fail_names'][:5])}…)" if cs["fail"] else ""))
        else:
            print(f"enabled '{args.enable}' — now scanned.")
        print(f"Active: {', '.join(r['active_sources'])}")
        return

    if args.disable:
        r = rules_fetch.disable(args.disable)
        print(f"disabled '{args.disable}'. Active: {', '.join(r['active_sources']) or '(none)'}")
        return


def cmd_yara(args) -> None:
    """Generate / collect / promote YARA rules."""
    _try_dotenv()
    from argus import yara_gen

    if args.list:
        r = yara_gen.list_rules()
        print(f"ACTIVE ({r['active_dir']}): {len(r['active'])}")
        for n in r["active"]:
            print(f"  * {n}")
        print(f"\nGENERATED / staged ({r['generated_dir']}): {len(r['generated'])}")
        for n in r["generated"]:
            print(f"  ? {n}")
        if r["generated"]:
            print("\nPromote a reviewed candidate:  python run.py yara --promote <name>")
        return

    if args.check:
        from argus import rule_quality, yara_gen as yg
        target = args.check
        p = Path(target)
        if not p.exists():
            for base in (yg._generated_dir(), config.YARA_RULES_DIR):
                cand = base / (target if target.endswith((".yar", ".yara")) else target + ".yar")
                if cand.exists():
                    p = cand; break
        q = rule_quality.check_file(p)
        print(f"rule: {p}")
        print(f"  compiles: {q['compiles']}" + ("" if q["verified"] else " (structural-only; yara not installed)"))
        if q.get("error"):
            print(f"  error: {q['error']}")
        print(f"  goodware scanned: {q['goodware_scanned']}  false-positive hits: {len(q['fp_hits'])}")
        for h in q["fp_hits"][:8]:
            print(f"    ! {h}")
        print(f"  VERDICT: {'PASS' if q['passed'] else 'FAIL'}")
        for r in q["reasons"]:
            print(f"    - {r}")
        return

    if args.promote:
        r = yara_gen.promote(args.promote, force=args.force)
        if r.get("error"):
            print("⛔ " + r["error"])
        else:
            print(f"promoted -> {r['path']} (now loaded by the scanner)")
        return

    if args.scan:
        from argus import yara_engine
        hits = yara_engine.scan_file(args.scan)
        print(f"{len(hits)} match(es): {', '.join(hits) if hits else '(none)'}")
        return

    if args.gen:
        rule = yara_gen.generate_rule(args.gen, name=args.name)
        if rule.get("error"):
            print("ERROR: " + rule["error"]); return
        print(rule["text"])
        if args.save:
            path = yara_gen.save_generated(rule)
            print(f"\n[staged -> {path}]  review it, then: python run.py yara --promote {rule['name']}")
        else:
            print("\n(not saved; add --save to stage it in rules/generated/)")
        return

    print("Nothing to do. Try: --gen <sample> [--save] | --list | --promote <name> | --scan <file>")


def cmd_publish(args) -> None:
    """Human-gated publishing of an approved finding (dry-run unless --confirm)."""
    _try_dotenv()
    from argus import publish, autohunt

    if args.list:
        pend = autohunt.pending_reviews()
        if not pend:
            print("review queue is empty.")
            return
        print(f"{len(pend)} draft(s):\n")
        for p in pend:
            print(f"  [{p['status']:>13}] {p['dir']}")
        print("\nApprove:  python run.py publish <draft> --approve")
        print("Publish:  python run.py publish <draft> --to vt,twitter,linkedin [--confirm]")
        return

    if not args.draft:
        print("Specify a draft folder (or --list). e.g. python run.py publish <sha_dir> --approve")
        return

    if args.approve:
        r = publish.approve(args.draft)
        print(r.get("error") or f"approved -> {r['dir']}\nNow: python run.py publish {args.draft} --to vt,twitter --confirm")
        return

    targets = [t.strip() for t in (args.to or "").split(",") if t.strip()]
    if not targets:
        print("Nothing to do. Use --to vt,twitter,linkedin (and --confirm to actually send).")
        return

    res = publish.publish(args.draft, targets, confirm=args.confirm, force=args.force)
    if res.get("error"):
        print("ERROR: " + res["error"]); return
    if res.get("blocked"):
        print("⛔ BLOCKED: " + res["blocked"]); return

    mode = "LIVE PUBLISH" if not res["dry_run"] else "DRY RUN (nothing sent — add --confirm to publish)"
    print(f"== {mode} ==")
    if res.get("safety_override"):
        print("  ⚠ safety guardrail OVERRIDDEN with --force")
    for r in res["results"]:
        if r.get("skipped"):
            print(f"  - {r['target']:>8}: skipped ({r['detail']})")
        else:
            flag = "OK " if r.get("ok") else "ERR"
            print(f"  {flag} {r['target']:>8}: {r['detail']}")


def cmd_enrich(args) -> None:
    """Corroborate a detonation's verdict with VirusTotal (host-side; needs VT_API_KEY)."""
    _try_dotenv()
    from argus.intel import virustotal
    if not virustotal.available():
        print("No VT_API_KEY set. Add it to .env (free key from virustotal.com) and retry.")
        return

    target = Path(args.run)
    fj = target / "findings.json" if target.is_dir() else target
    if not fj.exists():
        print(f"No findings.json at {fj}. Point --run at a runs/dynamic/<...> folder.")
        return
    struct = json.loads(fj.read_text(encoding="utf-8"))
    print(f"Looking up SHA-256 {struct.get('sha256','?')[:16]}… on VirusTotal …")
    virustotal.enrich(struct)
    fj.write_text(json.dumps(struct, indent=2), encoding="utf-8")

    vt = struct.get("vt", {})
    print(f"  VirusTotal: {vt.get('summary','n/a')}")
    if vt.get("names"):
        print(f"  names: {', '.join(vt['names'])}")
    if struct.get("vt_conflict"):
        print(f"  ⚠ CONFLICT: {struct['vt_conflict']}")
    print(f"  verdict: {struct.get('verdict_text','?')}  "
          f"[confidence {struct.get('confidence','?')}% · {struct.get('confidence_label','?')}]")
    print(f"  updated -> {fj}")


def cmd_autohunt(args) -> None:
    """Autonomous loop: queue -> detonate -> analyze -> verdict -> ledger + review queue."""
    _try_dotenv()
    from argus import autohunt

    if args.reviews:
        pending = autohunt.pending_reviews()
        if not pending:
            print("review queue is empty.")
            return
        print(f"{len(pending)} draft(s) pending review:\n")
        for p in pending:
            print(f"  [{p['status']}] {p['dir']}")
            if p["tweet"]:
                print(f"      tweet: {p['tweet'][:120]}")
        print("\nApprove/publish is human-gated — nothing is posted automatically.")
        return

    def emit(ev):
        t = ev.get("type")
        if t == "loop_start":
            print(f"AUTOHUNT — draining queue: {ev['queue']}  (once={ev['once']})\n")
        elif t == "start":
            print(f"▶ detonating {ev['sample']} ...")
        elif t == "rule_staged":
            print(f"  ⊕ staged candidate YARA rule -> {ev['rule']}")
        elif t == "drafted":
            print(f"  ⚠ {ev['sample']}: {ev['verdict'].upper()} · +{ev.get('xp',0)} XP "
                  f"(Lv {ev.get('level','?')}) · draft -> {ev['draft']}")
        elif t == "done":
            print(f"  ✓ {ev['sample']}: {ev['verdict']}")
        elif t == "blocked":
            print(f"  ⛔ {ev['sample']}: BLOCKED — credentials present: {', '.join(ev.get('keys', []))}")
        elif t == "error":
            print(f"  ✗ {ev['sample']}: {ev.get('error')}")
        elif t == "halt":
            print(f"\n⛔ HALTED — {ev.get('reason')}")
        elif t == "idle":
            print(f"  (queue empty — waiting {ev['waiting']}s; Ctrl-C to stop)")
        elif t == "loop_end":
            print("\nAUTOHUNT done." + ("" if ev.get("processed") else " (nothing new in queue.)"))

    autohunt.loop(queue_dir=args.queue, timeout=args.timeout,
                  once=args.once, interval=args.interval, on_event=emit)


def cmd_progression(args) -> None:
    from argus import progression
    if args.reset:
        progression.reset()
        print("progression state reset.")
        return
    print(progression.leaderboard())


def cmd_devroom(args) -> None:
    _try_dotenv()
    from argus.devroom import watch, list_room, init_room

    if args.list:
        init_room()
        print(list_room())
        return

    watch(args.agent, interval=max(2.0, args.interval), once=args.once)


def main() -> None:
    p = argparse.ArgumentParser(prog="argus", description="Autonomous VR agent (Windows LPE / binary RE).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index", help="(re)build the dataset from the vault").set_defaults(func=cmd_index)

    pr = sub.add_parser("retrieve", help="test RAG retrieval (no API key needed)")
    pr.add_argument("query")
    pr.add_argument("-k", type=int, default=4)
    pr.set_defaults(func=cmd_retrieve)

    pa = sub.add_parser("ask", help="short Q&A run")
    pa.add_argument("question")
    pa.add_argument("--max-steps", type=int, default=0)
    pa.set_defaults(func=cmd_ask)

    pw = sub.add_parser("web", help="launch the web console")
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=8765)
    pw.set_defaults(func=cmd_web)

    pap = sub.add_parser("app", help="launch the native desktop application window")
    pap.set_defaults(func=cmd_app)

    pt = sub.add_parser("triage", help="static malware triage of a sample/zip")
    pt.add_argument("sample")
    pt.add_argument("--max-steps", type=int, default=0)
    pt.set_defaults(func=cmd_triage)

    pre = sub.add_parser("reanalyze", help="re-run auto-analysis on an existing run folder (converts procmon, no re-detonation)")
    pre.add_argument("run", help="a runs/dynamic/<...> folder")
    pre.set_defaults(func=cmd_reanalyze)

    pdyn = sub.add_parser("detonate", help="DYNAMIC malware analysis — executes sample in VM only!")
    pdyn.add_argument("sample")
    pdyn.add_argument("--timeout", type=int, default=120, help="max execution seconds")
    pdyn.set_defaults(func=cmd_detonate)

    pf = sub.add_parser("fetch", help="pull samples from MalwareBazaar into intake/ (VM only!)")
    pf.add_argument("--limit", type=int, default=25)
    pf.add_argument("--tag", default=None, help="filter by family/tag, e.g. AgentTesla")
    pf.set_defaults(func=cmd_fetch)

    pwt = sub.add_parser("watch", help="autonomously triage new files in intake/ (static)")
    pwt.add_argument("--interval", type=int, default=60, help="poll seconds")
    pwt.add_argument("--once", action="store_true", help="one pass then exit")
    pwt.add_argument("--llm", action="store_true", help="also write an LLM analyst summary per sample (costs tokens)")
    pwt.set_defaults(func=cmd_watch)

    ph = sub.add_parser("hunt", help="full hunt on a target")
    ph.add_argument("task")
    ph.add_argument("--max-steps", type=int, default=0)
    ph.set_defaults(func=cmd_hunt)

    pc = sub.add_parser("collab", help="two-agent debate collaboration")
    pc.add_argument("task")
    pc.add_argument("--agent-a", default=None, help="model for agent A (primary); default = provider flagship")
    pc.add_argument("--agent-b", default=None, help="model for agent B (critic); default = provider's secondary")
    pc.add_argument("--rounds", type=int, default=6, help="max debate rounds")
    pc.set_defaults(func=cmd_collab)

    pwf = sub.add_parser("workflow", help="autonomous multi-agent task queue")
    pwf.add_argument("--agent", default="opencode", choices=("opencode", "opus5"),
                     help="which agent identity to run as")
    pwf.add_argument("--once", action="store_true", help="single pass (default: loop forever)")
    pwf.add_argument("--interval", type=int, default=10, help="poll interval in seconds")
    pwf.add_argument("--seed", action="store_true", help="write initial tasks (if empty)")
    pwf.set_defaults(func=cmd_workflow)

    pnp = sub.add_parser("netplan", help="classify static IOCs into sinkhole/answer/noise buckets")
    pnp.add_argument("report", help="path to the static IOC report (e.g. IOC1.txt)")
    pnp.add_argument("--out", default=None, help="output dir (default: <report_dir>/netplan)")
    pnp.set_defaults(func=cmd_netplan)

    pdf = sub.add_parser("diff", help="diff two detonation runs -> C2-gated (malicious) behavior")
    pdf.add_argument("run_a", help="untouched run dir (FakeNet answering C2)")
    pdf.add_argument("run_b", help="sinkholed run dir (C2 dead)")
    pdf.add_argument("--out", default=None, help="write malicious_diff.md to this dir")
    pdf.set_defaults(func=cmd_diff)

    sub.add_parser("doctor", help="preflight: check VM readiness + network mode").set_defaults(func=cmd_doctor)

    pio = sub.add_parser("ioc", help="extract shareable IOCs (hashes/IPs/domains/files) from a run")
    pio.add_argument("run", help="a runs/dynamic/<...> folder")
    pio.add_argument("--defang", action="store_true", help="defang indicators for safe sharing (hxxp, [.])")
    pio.set_defaults(func=cmd_ioc)

    pst = sub.add_parser("selftest", help="validate the pipeline against known-answer samples")
    pst.add_argument("--manifest", default="validation/manifest.json", help="path to the validation manifest")
    pst.set_defaults(func=cmd_selftest)

    pms = sub.add_parser("memscan", help="Volatility3 cross-view memory forensics (hidden procs/drivers)")
    pms.add_argument("dump", nargs="?", default=None, help="path to a memory dump (.raw / .vmem / .dmp)")
    pms.add_argument("--acquire", metavar="OUT", help="acquire live memory via WinPmem to OUT")
    pms.set_defaults(func=cmd_memscan)

    pbs = sub.add_parser("bootscan", help="boot-chain differential forensics (rootkit/bootkit research)")
    pbs.add_argument("--baseline", action="store_true", help="capture the boot-chain baseline (before)")
    pbs.add_argument("--compare", action="store_true", help="diff vs baseline (after detonate + REBOOT)")
    pbs.add_argument("--show", action="store_true", help="print the current baseline summary")
    pbs.set_defaults(func=cmd_bootscan)

    prl = sub.add_parser("rules", help="fetch / enable community YARA rulesets")
    prl.add_argument("--sources", action="store_true", help="list available sources (default)")
    prl.add_argument("--fetch", metavar="NAME", help="download a source into staging")
    prl.add_argument("--all", action="store_true", help="fetch every source")
    prl.add_argument("--enable", metavar="NAME", help="add a fetched source to scanning")
    prl.add_argument("--disable", metavar="NAME", help="remove a source from scanning")
    prl.add_argument("--limit", type=int, default=400, help="max rules per source fetch")
    prl.set_defaults(func=cmd_rules)

    pyar = sub.add_parser("yara", help="generate / collect / promote YARA rules")
    pyar.add_argument("--gen", metavar="SAMPLE", help="generate a candidate rule from a sample")
    pyar.add_argument("--name", help="rule name for --gen (defaults to the filename)")
    pyar.add_argument("--save", action="store_true", help="stage the generated rule in rules/generated/")
    pyar.add_argument("--list", action="store_true", help="list active + staged rules")
    pyar.add_argument("--promote", metavar="NAME", help="move a staged rule into the active ruleset (quality-gated)")
    pyar.add_argument("--check", metavar="RULE", help="run the quality gate on a rule (compile + goodware FP scan)")
    pyar.add_argument("--force", action="store_true", help="promote even if the quality gate fails")
    pyar.add_argument("--scan", metavar="FILE", help="scan a file with the active ruleset")
    pyar.set_defaults(func=cmd_yara)

    pub = sub.add_parser("publish", help="human-gated publish of an approved finding (VT/Twitter/LinkedIn)")
    pub.add_argument("draft", nargs="?", default=None, help="review-queue draft folder (name or path)")
    pub.add_argument("--list", action="store_true", help="list drafts and their status")
    pub.add_argument("--approve", action="store_true", help="mark a reviewed draft as approved")
    pub.add_argument("--to", default="", help="comma targets: vt,twitter,linkedin")
    pub.add_argument("--confirm", action="store_true", help="actually send (default is a dry run)")
    pub.add_argument("--force", action="store_true", help="override the false-positive safety refusal")
    pub.set_defaults(func=cmd_publish)

    pen = sub.add_parser("enrich", help="corroborate a detonation verdict with VirusTotal (host-side)")
    pen.add_argument("run", help="a runs/dynamic/<...> folder or a findings.json path")
    pen.set_defaults(func=cmd_enrich)

    pah = sub.add_parser("autohunt", help="autonomous loop: detonate a sample queue, analyze, draft writeups")
    pah.add_argument("--queue", default=None, help="directory of samples (default: intake/)")
    pah.add_argument("--timeout", type=int, default=120, help="per-sample detonation seconds")
    pah.add_argument("--once", action="store_true", help="one drain pass then exit")
    pah.add_argument("--interval", type=int, default=30, help="poll seconds when queue is empty")
    pah.add_argument("--reviews", action="store_true", help="list drafts pending human review and exit")
    pah.set_defaults(func=cmd_autohunt)

    pp = sub.add_parser("progression", help="show the hunter leaderboard / XP standings")
    pp.add_argument("--leaderboard", action="store_true", help="print standings (default)")
    pp.add_argument("--reset", action="store_true", help="wipe progression state")
    pp.set_defaults(func=cmd_progression)

    pdev = sub.add_parser("devroom", help="live development chat room (shared file)")
    pdev.add_argument("--agent", default="opencode", choices=("opencode", "opus5", "muhammed"),
                      help="which identity to chat as")
    pdev.add_argument("--once", action="store_true", help="check once and exit")
    pdev.add_argument("--interval", type=float, default=3.0, help="poll interval in seconds")
    pdev.add_argument("--list", action="store_true", help="print the room transcript")
    pdev.set_defaults(func=cmd_devroom)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
