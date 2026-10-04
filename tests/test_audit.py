import json
import multiprocessing as mp
from pathlib import Path

from aegisq.audit import AuditLog


def _writer(path: str, n: int, tag: str) -> None:
    log = AuditLog(path)
    for i in range(n):
        log.append("test.event", {"tag": tag, "i": i})


def test_chain_verifies_and_scrubs_secrets(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("one", {"x": 1})
    e = log.append("two", {"nested": {"api_key": "sk-123", "token": "t", "ok": [{"password": "p"}]}}, actor="alice")
    assert e["seq"] == 2 and e["actor"] == "alice"
    assert e["data"]["nested"]["api_key"] == "[redacted]" and e["data"]["nested"]["ok"][0]["password"] == "[redacted]"
    assert "sk-123" not in (tmp_path / "a.jsonl").read_text()
    r = log.verify()
    assert r.ok and r.entries == 2
    assert [x["event"] for x in log.tail(5)] == ["one", "two"]
    assert [x["event"] for x in log.tail(5, "tw")] == ["two"]


def _lines(p: Path) -> list[str]:
    return p.read_text().splitlines()


def test_tampering_is_detected(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(5):
        log.append("e", {"i": i})
    original = _lines(p)

    # 1. edit a field
    edited = json.loads(original[2])
    edited["data"]["i"] = 99
    p.write_text("\n".join(original[:2] + [json.dumps(edited)] + original[3:]) + "\n")
    r = log.verify()
    assert not r.ok and r.bad_seq == 3 and "altered" in (r.error or "")

    # 2. delete an entry
    p.write_text("\n".join(original[:2] + original[3:]) + "\n")
    assert not log.verify().ok

    # 3. reorder
    p.write_text("\n".join([original[1], original[0], *original[2:]]) + "\n")
    assert not log.verify().ok

    # 4. truncated garbage
    p.write_text("\n".join(original) + "\n{not json\n")
    assert not log.verify().ok

    # 5. recompute hashes without the key: caught when the chain is keyed
    keyed = tmp_path / "k.jsonl"
    klog = AuditLog(keyed, key=b"secret")
    for i in range(3):
        klog.append("e", {"i": i})
    forged_lines = []
    prev = "0" * 64
    unkeyed = AuditLog(tmp_path / "scratch.jsonl", key=b"")
    unkeyed.key = None
    for line in _lines(keyed):
        entry = json.loads(line)
        entry.pop("hash")
        entry["prev"] = prev
        entry["data"]["i"] = 1000
        entry["hash"] = unkeyed._digest(entry)
        prev = entry["hash"]
        forged_lines.append(json.dumps(entry))
    keyed.write_text("\n".join(forged_lines) + "\n")
    assert not klog.verify().ok
    assert AuditLog(keyed, key=b"wrong").verify().ok is False


def test_concurrent_writers_keep_one_chain(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    ctx = mp.get_context("spawn")  # spawn exists on every OS
    procs = [ctx.Process(target=_writer, args=(str(p), 40, f"w{i}")) for i in range(4)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(30)
    r = AuditLog(p).verify()
    assert r.ok and r.entries == 160


def test_empty_log_verifies(tmp_path: Path) -> None:
    assert AuditLog(tmp_path / "none.jsonl").verify().ok


def test_incremental_verify_still_catches_old_tampering(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    for i in range(50):
        log.append("e", {"i": i})
    assert log.verify().ok and log._checkpoint is not None
    for i in range(5):
        log.append("e", {"i": 100 + i})
    r = log.verify()
    assert r.ok and r.entries == 55  # resumed from the checkpoint
    lines = _lines(p)
    lines[3] = lines[3].replace('"i":3', '"i":4')  # rewrite an entry that was already verified
    p.write_text("\n".join(lines) + "\n")
    r = log.verify()
    assert not r.ok and r.bad_seq == 4
    # truncation is caught too
    log2 = AuditLog(tmp_path / "b.jsonl")
    for i in range(10):
        log2.append("e", {"i": i})
    assert log2.verify().ok
    (tmp_path / "b.jsonl").write_text("\n".join(_lines(tmp_path / "b.jsonl")[:5]) + "\n")
    assert log2.verify().entries == 5  # shorter file -> full re-verification of what remains


def test_tail_matches_full_read_across_chunk_boundaries(tmp_path: Path, monkeypatch) -> None:
    import aegisq.audit as audit_mod

    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(300):
        log.append("even" if i % 2 == 0 else "odd", {"i": i, "pad": "x" * (i % 37)})
    everything = list(log.entries())
    for chunk in (17, 100, 4096, 1 << 16):
        monkeypatch.setattr(audit_mod, "_TAIL_CHUNK", chunk)
        assert log.tail(25) == everything[-25:]
        assert log.tail(7, "odd") == [e for e in everything if e["event"] == "odd"][-7:]
        assert log.tail(1000) == everything
        assert log.tail(5, "none") == []
    assert log.tail(0) == everything
    assert AuditLog(tmp_path / "missing.jsonl").tail(5) == []
