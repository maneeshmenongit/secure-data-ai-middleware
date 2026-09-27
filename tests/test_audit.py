import json
from datetime import datetime, timedelta

import pytest

from datasec.audit import GENESIS, AuditLog, entry_hash
from datasec.errors import DataSecError


def rec(**over):
    base = dict(
        sink="llm", name="chat", effect="allow", reason="ok", rule=None,
        trust="USER", source="user:1", labels=["pii"], tally={"EMAIL": 1},
    )
    base.update(over)
    return base


def make_file_log(tmp_path, n=3):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(n):
        log.append(**rec(name=f"n{i}"))
    return path, log


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def write_lines(path, entries):
    path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))


def test_empty_log():
    log = AuditLog()
    assert len(log) == 0
    assert log.head == GENESIS
    assert log.verify()


def test_append_chains_entries():
    log = AuditLog()
    a = log.append(**rec())
    b = log.append(**rec(name="two"))
    assert a.prev_hash == GENESIS
    assert b.prev_hash == a.hash
    assert log.head == b.hash
    assert list(log) == [a, b]
    assert len(log) == 2
    assert a.hash == entry_hash(GENESIS, a.body())
    assert log.verify()


def test_body_excludes_hashes():
    a = AuditLog().append(**rec())
    assert set(a.body()) == {
        "ts", "sink", "name", "effect", "reason", "rule",
        "trust", "source", "labels", "tally",
    }


def test_ts_is_utc_iso8601():
    a = AuditLog().append(**rec())
    assert datetime.fromisoformat(a.ts).utcoffset() == timedelta(0)


def test_labels_are_sorted():
    assert AuditLog().append(**rec(labels=["z", "a"])).labels == ["a", "z"]


def test_jsonl_roundtrip(tmp_path):
    path, log = make_file_log(tmp_path)
    loaded = AuditLog.load(path)
    assert list(loaded) == list(log)
    assert loaded.verify(expected_head=log.head)


def test_edited_field_detected(tmp_path):
    path, _ = make_file_log(tmp_path)
    entries = read_lines(path)
    entries[1]["effect"] = "deny"
    write_lines(path, entries)
    assert not AuditLog.load(path).verify()


def test_deleted_middle_entry_detected(tmp_path):
    path, _ = make_file_log(tmp_path)
    entries = read_lines(path)
    del entries[1]
    write_lines(path, entries)
    assert not AuditLog.load(path).verify()


def test_reordered_entries_detected(tmp_path):
    path, _ = make_file_log(tmp_path)
    entries = read_lines(path)
    entries[0], entries[1] = entries[1], entries[0]
    write_lines(path, entries)
    assert not AuditLog.load(path).verify()


def test_tail_truncation_needs_expected_head(tmp_path):
    path, log = make_file_log(tmp_path)
    head = log.head
    write_lines(path, read_lines(path)[:-1])
    loaded = AuditLog.load(path)
    assert loaded.verify() is True
    assert loaded.verify(expected_head=head) is False


def test_expected_head_mismatch_fails_intact_log(tmp_path):
    path, _ = make_file_log(tmp_path)
    assert not AuditLog.load(path).verify(expected_head="f" * 64)


def test_corrupt_line_raises(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n")
    with pytest.raises(DataSecError):
        AuditLog.load(path)


def test_missing_field_raises(tmp_path):
    path, _ = make_file_log(tmp_path)
    entries = read_lines(path)
    del entries[0]["hash"]
    write_lines(path, entries)
    with pytest.raises(DataSecError):
        AuditLog.load(path)


def test_file_write_failure_leaves_memory_unchanged(tmp_path):
    log = AuditLog(tmp_path / "missing-dir" / "audit.jsonl")
    with pytest.raises(OSError):
        log.append(**rec())
    assert len(log) == 0


def test_reopening_existing_file_continues_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append(**rec(name="first"))
    reopened = AuditLog(path)
    assert len(reopened) == 1
    reopened.append(**rec(name="second"))
    assert AuditLog.load(path).verify(expected_head=reopened.head)


def test_reopening_tampered_file_refuses(tmp_path):
    path, _ = make_file_log(tmp_path)
    entries = read_lines(path)
    entries[0]["effect"] = "deny"
    write_lines(path, entries)
    with pytest.raises(DataSecError):
        AuditLog(path)


def test_concurrent_appends_keep_the_chain_intact():
    import threading

    log = AuditLog()

    def worker():
        for _ in range(5000):
            log.append(**rec())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(log) == 40_000
    assert log.verify()
