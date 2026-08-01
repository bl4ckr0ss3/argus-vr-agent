"""Tests for Sigma behavioral rule generation."""
import argus.sigma_gen as sg


def _struct():
    return {
        "sample": "mal.exe", "sha256": "a" * 64,
        "spawned": ["C:/Windows/System32/cmd.exe", "C:/Windows/System32/powershell.exe"],
        "net": ["labvm:5 -> 93.184.216.34:443", "conn http://evil-c2.example/x"],
        "persistence": [r"HKEY_LOCAL_MACHINE\...\CurrentVersion\Run\Updater"],
        "staged_payloads": ["C:/Users/lab/AppData/Roaming/payload.exe"],
    }


def test_all_four_categories():
    rules = sg.rules_from(_struct())
    cats = {r["category"] for r in rules}
    assert cats == {"process_creation", "network_connection", "registry_set", "file_event"}


def test_process_rule_uses_basenames():
    rules = sg.rules_from(_struct())
    proc = next(r for r in rules if r["category"] == "process_creation")
    assert proc["selection"]["Image|endswith"] == ["\\cmd.exe", "\\powershell.exe"]


def test_network_rule_has_ip_and_domain():
    rules = sg.rules_from(_struct())
    net = next(r for r in rules if r["category"] == "network_connection")
    assert net["selection"]["DestinationIp"] == ["93.184.216.34"]
    assert "evil-c2.example" in net["selection"]["DestinationHostname"]


def test_render_is_valid_sigma_shape():
    rules = sg.rules_from(_struct())
    text = sg.render(rules[0])
    for key in ("title:", "id:", "logsource:", "category:", "detection:", "condition: selection", "level:"):
        assert key in text


def test_deterministic_ids():
    a = sg._rule_id("a" * 64, "process_creation")
    b = sg._rule_id("a" * 64, "process_creation")
    c = sg._rule_id("a" * 64, "network_connection")
    assert a == b and a != c
    assert len(a.split("-")) == 5          # uuid-shaped


def test_yaml_quotes_backslashes():
    # a registry path with backslashes must be single-quoted, not break YAML
    text = sg.render({"category": "registry_set", "title": "t", "tags": ["attack.t1547.001"],
                      "level": "high", "sha": "x",
                      "selection": {"TargetObject|contains": [r"HKLM\Software\Run"]}})
    assert r"'HKLM\Software\Run'" in text


def test_empty_struct_no_rules():
    assert sg.generate({})["count"] == 0


def test_generate_bundles_with_separator():
    out = sg.generate(_struct())
    assert out["count"] == 4
    assert out["text"].count("\n---\n") == 3    # 4 rules -> 3 separators
