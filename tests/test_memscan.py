"""Tests for the Volatility3 cross-view analysis (pure logic; no dump/vol needed)."""
import argus.memscan as ms


def test_clean_no_findings():
    pslist = [{"PID": 4, "ImageFileName": "System"}, {"PID": 500, "ImageFileName": "svchost.exe"}]
    psscan = [{"PID": 4, "ImageFileName": "System"}, {"PID": 500, "ImageFileName": "svchost.exe"}]
    modules = [{"Name": "ntoskrnl.exe", "Base": "0x1"}, {"Name": "tcpip.sys", "Base": "0x2"}]
    modscan = list(modules)
    assert ms.analyze(pslist, psscan, modules, modscan, []) == []


def test_hidden_process_is_critical():
    pslist = [{"PID": 4, "ImageFileName": "System"}]
    psscan = [{"PID": 4, "ImageFileName": "System"}, {"PID": 6660, "ImageFileName": "evil.exe"}]
    f = ms.analyze(pslist, psscan, [], [], [])
    hit = [x for x in f if x["what"] == "hidden process (DKOM)"]
    assert hit and hit[0]["severity"] == "CRITICAL" and "6660" in hit[0]["detail"]


def test_hidden_driver_is_critical():
    modules = [{"Name": "ntoskrnl.exe", "Base": "0x1"}]
    modscan = [{"Name": "ntoskrnl.exe", "Base": "0x1"}, {"Name": "rootkit.sys", "Base": "0xdead"}]
    f = ms.analyze([], [], modules, modscan, [])
    hit = [x for x in f if x["what"] == "hidden driver"]
    assert hit and hit[0]["severity"] == "CRITICAL" and "rootkit.sys" in hit[0]["detail"]


def test_malfind_is_high():
    malfind = [{"PID": 1234, "Process": "explorer.exe", "Protection": "PAGE_EXECUTE_READWRITE"}]
    f = ms.analyze([], [], [], [], malfind)
    hit = [x for x in f if x["what"] == "injected code (malfind)"]
    assert hit and hit[0]["severity"] == "HIGH" and "1234" in hit[0]["detail"]


def test_failed_plugin_does_not_false_positive():
    # pslist failed (None) -> we must NOT treat every psscan proc as hidden
    psscan = [{"PID": 4, "ImageFileName": "System"}, {"PID": 9, "ImageFileName": "x"}]
    f = ms.analyze(None, psscan, None, None, None)
    assert f == []


def test_ranking_critical_first():
    pslist = [{"PID": 4}]
    psscan = [{"PID": 4}, {"PID": 99, "ImageFileName": "hid.exe"}]
    malfind = [{"PID": 1, "Process": "a", "Protection": "RWX"}]
    f = ms.analyze(pslist, psscan, [], [], malfind)
    assert f[0]["severity"] == "CRITICAL"
