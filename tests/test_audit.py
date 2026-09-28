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


def test_extra_is_hashed_when_present(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append(**rec(), extra={"encryption": "key:k1"})
    entries = read_lines(path)
    entries[0]["extra"] = {"encryption": "unavailable"}
    write_lines(path, entries)
    assert not AuditLog.load(path).verify()


def test_logs_without_extra_field_still_verify(tmp_path):
    path, log = make_file_log(tmp_path)
    entries = read_lines(path)
    for e in entries:
        del e["extra"]  # simulate a Phase 1 log file
    write_lines(path, entries)
    assert AuditLog.load(path).verify(expected_head=log.head)


def checkpointed(tmp_path, n=3, every=100):
    from datasec.crypto import LocalKeyProvider

    signer = LocalKeyProvider()
    path, cp = tmp_path / "audit.jsonl", tmp_path / "audit.checkpoint"
    log = AuditLog(path, signer=signer, checkpoint_path=cp, checkpoint_every=every)
    for i in range(n):
        log.append(**rec(name=f"n{i}"))
    log.close()
    return path, cp, signer, log


def test_checkpoint_roundtrip(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, signer, log = checkpointed(tmp_path)
    cp = SignedCheckpoint.read(cp_path)
    assert (cp.head, cp.count) == (log.head, 3)
    assert cp.is_valid(signer)
    assert AuditLog.load(path).verify(checkpoint=cp, verifier=signer)


def test_truncation_past_checkpoint_detected(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, signer, _ = checkpointed(tmp_path)
    write_lines(path, read_lines(path)[:-1])
    assert not AuditLog.load(path).verify(checkpoint=SignedCheckpoint.read(cp_path), verifier=signer)
    with pytest.raises(DataSecError):
        AuditLog(path, signer=signer, checkpoint_path=cp_path)


def test_full_chain_rewrite_detected(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, signer, _ = checkpointed(tmp_path)
    entries = read_lines(path)
    entries[0]["effect"] = "deny"
    prev = GENESIS
    for e in entries:
        body = {k: v for k, v in e.items() if k not in ("prev_hash", "hash")}
        if not body.get("extra"):
            body.pop("extra", None)
        e["prev_hash"], e["hash"] = prev, entry_hash(prev, body)
        prev = e["hash"]
    write_lines(path, entries)
    loaded = AuditLog.load(path)
    assert loaded.verify() is True  # chain alone is fooled
    assert not loaded.verify(checkpoint=SignedCheckpoint.read(cp_path), verifier=signer)


def test_forged_checkpoint_rejected(tmp_path):
    from dataclasses import replace

    from datasec.audit import SignedCheckpoint
    from datasec.crypto import LocalKeyProvider

    _, cp_path, signer, _ = checkpointed(tmp_path)
    cp = SignedCheckpoint.read(cp_path)
    assert not replace(cp, head="f" * 64).is_valid(signer)
    assert not cp.is_valid(LocalKeyProvider())


def test_appends_after_checkpoint_still_verify(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, signer, _ = checkpointed(tmp_path)
    cp = SignedCheckpoint.read(cp_path)
    reopened = AuditLog(path, signer=signer, checkpoint_path=cp_path)
    reopened.append(**rec(name="later"))
    assert AuditLog.load(path).verify(checkpoint=cp, verifier=signer)


def test_periodic_checkpoint(tmp_path):
    from datasec.audit import SignedCheckpoint
    from datasec.crypto import LocalKeyProvider

    signer = LocalKeyProvider()
    cp_path = tmp_path / "audit.checkpoint"
    log = AuditLog(tmp_path / "audit.jsonl", signer=signer, checkpoint_path=cp_path, checkpoint_every=2)
    for i in range(5):
        log.append(**rec(name=f"n{i}"))
    assert SignedCheckpoint.read(cp_path).count == 4


def test_deleted_log_with_checkpoint_refuses(tmp_path):
    path, cp_path, signer, _ = checkpointed(tmp_path)
    path.unlink()
    with pytest.raises(DataSecError):
        AuditLog(path, signer=signer, checkpoint_path=cp_path)


def test_signer_requires_checkpoint_path():
    from datasec.crypto import LocalKeyProvider

    with pytest.raises(ValueError):
        AuditLog(signer=LocalKeyProvider())


def test_checkpoint_without_verifier_fails(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, _, _ = checkpointed(tmp_path)
    assert not AuditLog.load(path).verify(checkpoint=SignedCheckpoint.read(cp_path))


def test_corrupt_checkpoint_file_raises(tmp_path):
    from datasec.audit import SignedCheckpoint

    cp_path = tmp_path / "audit.checkpoint"
    cp_path.write_text("not json")
    with pytest.raises(DataSecError):
        SignedCheckpoint.read(cp_path)


def test_concurrent_appends_with_checkpoints(tmp_path):
    import threading

    from datasec.audit import SignedCheckpoint
    from datasec.crypto import LocalKeyProvider

    signer = LocalKeyProvider()
    path, cp_path = tmp_path / "audit.jsonl", tmp_path / "audit.checkpoint"
    log = AuditLog(path, signer=signer, checkpoint_path=cp_path, checkpoint_every=10)

    def worker():
        for _ in range(250):
            log.append(**rec())

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.close()
    assert AuditLog.load(path).verify(checkpoint=SignedCheckpoint.read(cp_path), verifier=signer)


def test_missing_checkpoint_for_existing_log_refuses(tmp_path):
    path, cp_path, signer, _ = checkpointed(tmp_path)
    write_lines(path, read_lines(path)[:-1])
    cp_path.unlink()
    with pytest.raises(DataSecError):
        AuditLog(path, signer=signer, checkpoint_path=cp_path)


def test_new_log_writes_initial_checkpoint(tmp_path):
    from datasec.audit import SignedCheckpoint
    from datasec.crypto import LocalKeyProvider

    cp_path = tmp_path / "audit.checkpoint"
    AuditLog(tmp_path / "audit.jsonl", signer=LocalKeyProvider(), checkpoint_path=cp_path)
    assert SignedCheckpoint.read(cp_path).count == 0


def test_checkpoint_requires_a_file_backed_log(tmp_path):
    from datasec.crypto import LocalKeyProvider

    with pytest.raises(ValueError):
        AuditLog(None, signer=LocalKeyProvider(), checkpoint_path=tmp_path / "cp")


def test_sealed_value_cannot_be_passed_off_as_checkpoint(tmp_path):
    from datasec.audit import SignedCheckpoint
    from datasec.crypto import seal

    path, cp_path, signer, log = checkpointed(tmp_path)
    cp = SignedCheckpoint.read(cp_path)
    forged = seal(signer, cp.claims())  # same key, same canonical JSON
    assert not SignedCheckpoint(cp.head, cp.count, cp.ts, forged.key_id, forged.token).is_valid(signer)


def test_checkpoint_every_must_be_positive(tmp_path):
    from datasec.crypto import LocalKeyProvider

    with pytest.raises(ValueError):
        AuditLog(tmp_path / "a.jsonl", signer=LocalKeyProvider(), checkpoint_path=tmp_path / "cp",
                 checkpoint_every=0)


def test_checkpoint_file_is_private(tmp_path):
    import stat

    _, cp_path, _, _ = checkpointed(tmp_path)
    assert stat.S_IMODE(cp_path.stat().st_mode) == 0o600


def test_context_manager_writes_final_checkpoint(tmp_path):
    from datasec.audit import SignedCheckpoint
    from datasec.crypto import LocalKeyProvider

    cp_path = tmp_path / "cp"
    with AuditLog(tmp_path / "a.jsonl", signer=LocalKeyProvider(), checkpoint_path=cp_path) as log:
        log.append(**rec())
    assert SignedCheckpoint.read(cp_path).count == 1


def test_load_with_checkpoint_verifies(tmp_path):
    from datasec.audit import SignedCheckpoint

    path, cp_path, signer, _ = checkpointed(tmp_path)
    cp = SignedCheckpoint.read(cp_path)
    assert len(AuditLog.load(path, checkpoint=cp, verifier=signer)) == 3
    write_lines(path, read_lines(path)[:-1])
    with pytest.raises(DataSecError):
        AuditLog.load(path, checkpoint=cp, verifier=signer)
