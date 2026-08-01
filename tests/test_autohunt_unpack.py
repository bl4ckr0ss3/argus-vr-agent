"""Tests for autohunt auto-unpacking zipped samples in the queue."""
import zipfile

import config
import argus.autohunt as ah


def test_iter_queue_unpacks_zip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / "q")
    queue = tmp_path / "intake"
    queue.mkdir()

    # a zip containing a PE (MZ) file named by a fake hash (no extension)
    pe_bytes = b"MZ" + b"\x90" * 128
    z = queue / "abc123.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("deadbeefdeadbeef", pe_bytes)

    yielded = list(ah._iter_queue(queue))
    assert len(yielded) == 1
    assert yielded[0].read_bytes() == pe_bytes          # the extracted PE
    assert "q" in str(yielded[0])                        # unpacked into quarantine


def test_iter_queue_skips_non_pe_zip_members(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "QUARANTINE_DIR", tmp_path / "q")
    queue = tmp_path / "intake"
    queue.mkdir()
    z = queue / "notes.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", b"just text, not a PE")
    # no PE, no sample-ext member -> nothing yielded
    assert list(ah._iter_queue(queue)) == []


def test_iter_queue_plain_exe_still_works(tmp_path):
    queue = tmp_path / "intake"
    queue.mkdir()
    (queue / "mal.exe").write_bytes(b"MZ...")
    out = list(ah._iter_queue(queue))
    assert len(out) == 1 and out[0].name == "mal.exe"
