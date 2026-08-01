"""Tests for community YARA ruleset fetch + the enable/disable gate (no network)."""
import json

import config
import argus.rules_fetch as rf


def _fake_get(url, headers=None, timeout=30):
    if "api.github.com" in url:
        return json.dumps([
            {"type": "file", "name": "apt_x.yar", "download_url": "https://raw/apt_x.yar"},
            {"type": "file", "name": "trojan_y.yara", "download_url": "https://raw/trojan_y.yara"},
            {"type": "file", "name": "README.md", "download_url": "https://raw/README.md"},
            {"type": "dir", "name": "subdir"},
        ]).encode()
    return b"rule sample_rule { condition: true }"


def test_list_sources():
    names = {s["name"] for s in rf.list_sources()}
    assert "signature-base" in names and "elastic" in names


def test_fetch_unknown_source():
    r = rf.fetch("does-not-exist")
    assert r.get("error") and "unknown source" in r["error"]


def test_fetch_writes_only_yar(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(rf, "_http_get", _fake_get)
    r = rf.fetch("signature-base")
    assert r["ok"] and r["count"] == 2          # .yar + .yara, README.md ignored
    files = {p.name for p in (tmp_path / "rules" / "community" / "signature-base").glob("*")}
    assert files == {"apt_x.yar", "trojan_y.yara"}


def test_enable_requires_fetch(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    r = rf.enable("elastic")
    assert r.get("error") and "not fetched" in r["error"]


def test_enable_disable_and_active_files(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(rf, "_http_get", _fake_get)
    rf.fetch("signature-base")

    # staged but not active until enabled
    assert rf.active_community_files() == []

    en = rf.enable("signature-base")
    assert en["ok"] and "signature-base" in en["active_sources"]
    active = {p.name for p in rf.active_community_files()}
    assert active == {"apt_x.yar", "trojan_y.yara"}

    rf.disable("signature-base")
    assert rf.active_community_files() == []


def test_enabled_source_feeds_scanner(tmp_path, monkeypatch):
    # yara_engine._rule_files must include enabled community rules
    monkeypatch.setattr(config, "YARA_RULES_DIR", tmp_path / "rules")
    monkeypatch.setattr(rf, "_http_get", _fake_get)
    rf.fetch("signature-base")
    rf.enable("signature-base")
    from argus import yara_engine
    names = {p.name for p in yara_engine._rule_files()}
    assert "apt_x.yar" in names and "trojan_y.yara" in names
