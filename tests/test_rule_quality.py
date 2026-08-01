"""Tests for the rule quality gate (compile + goodware FP scan) and promote gating."""
import config
import argus.rule_quality as rq
import argus.yara_gen as yg

_VALID = "rule t { condition: true }"


def test_structural_catches_bad():
    # no engine or engine: a clearly-broken rule must not pass compile
    assert rq.compile_ok("garbage with no rule block")["ok"] is False
    ok = rq.compile_ok(_VALID)
    assert ok["ok"] is True


def test_structural_specifics():
    assert rq._structural("rule x {}")[0] is False           # no condition
    assert rq._structural("condition: true")[0] is False     # no rule decl
    assert rq._structural("rule x { condition: true ")[0] is False  # unbalanced
    assert rq._structural(_VALID)[0] is True


def test_check_passes_clean(tmp_path, monkeypatch):
    gw = tmp_path / "gw"; gw.mkdir()
    (gw / "clean.exe").write_bytes(b"MZ clean binary")
    monkeypatch.setattr(config, "GOODWARE_DIR", gw)
    monkeypatch.setattr(rq, "_matches", lambda r, t: False)
    rf = tmp_path / "r.yar"; rf.write_text(_VALID, encoding="utf-8")
    q = rq.check_file(rf)
    assert q["passed"] and q["goodware_scanned"] == 1 and not q["fp_hits"]


def test_check_fails_when_too_broad(tmp_path, monkeypatch):
    gw = tmp_path / "gw"; gw.mkdir()
    (gw / "clean.exe").write_bytes(b"MZ clean binary")
    monkeypatch.setattr(config, "GOODWARE_DIR", gw)
    monkeypatch.setattr(rq, "_matches", lambda r, t: True)   # matches goodware -> too broad
    rf = tmp_path / "r.yar"; rf.write_text(_VALID, encoding="utf-8")
    q = rq.check_file(rf)
    assert not q["passed"] and q["fp_hits"]
    assert any("too broad" in r for r in q["reasons"])


def test_check_no_goodware_skips_fp(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "GOODWARE_DIR", tmp_path / "nonexistent")
    rf = tmp_path / "r.yar"; rf.write_text(_VALID, encoding="utf-8")
    q = rq.check_file(rf)
    assert q["passed"] and q["goodware_scanned"] == 0
    assert any("no goodware" in r for r in q["reasons"])


def test_promote_blocked_by_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    gen = tmp_path / "rules" / "generated"; gen.mkdir(parents=True)
    (gen / "ARGUS_x.yar").write_text("rule ARGUS_x { condition: true }", encoding="utf-8")

    monkeypatch.setattr(rq, "check_file",
                        lambda p: {"passed": False, "reasons": ["matches 3 goodware file(s) — too broad"]})
    r = yg.promote("ARGUS_x")
    assert r.get("error") and "quality gate failed" in r["error"]
    assert not (tmp_path / "rules" / "ARGUS_x.yar").exists()   # not promoted

    # --force bypasses the gate
    r2 = yg.promote("ARGUS_x", force=True)
    assert r2.get("ok") and (tmp_path / "rules" / "ARGUS_x.yar").exists()


def test_promote_allowed_when_gate_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    gen = tmp_path / "rules" / "generated"; gen.mkdir(parents=True)
    (gen / "ARGUS_ok.yar").write_text("rule ARGUS_ok { condition: true }", encoding="utf-8")
    monkeypatch.setattr(rq, "check_file", lambda p: {"passed": True, "reasons": []})
    r = yg.promote("ARGUS_ok")
    assert r.get("ok") and (tmp_path / "rules" / "ARGUS_ok.yar").exists()
