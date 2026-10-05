import json

import pytest

from datasec.adapters.gate import Mode, check
from datasec.audit import AuditLog
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import Provenance, TrustLevel, from_user, untrusted
from datasec.report import main, summarize


def build_log(path):
    p = SecurityPipeline(audit=AuditLog(path))
    ext = Provenance(TrustLevel.EXTERNAL, "tool:referee")
    for _ in range(2):
        check(p, Action("tool:privileged", "RunCommand", ext), ["python", "x.py"], Mode.SHADOW)
    check(p, Action("llm", "plan", from_user("", source="principal").provenance), "mail jane@example.com", Mode.ENFORCE)
    p.guard(Action("tool:privileged", "pay", untrusted("", source="web").provenance), "wire")
    return p


def test_summary_counts(tmp_path):
    p = build_log(tmp_path / "a.jsonl")
    s = summarize(list(p.audit))
    assert s["by_sink_effect_mode"][("tool:privileged", "deny", "shadow")] == 2
    assert s["by_sink_effect_mode"][("llm", "redact", "enforce")] == 1
    assert s["by_sink_effect_mode"][("tool:privileged", "deny", "enforce")] == 1
    assert s["shadow_denials"][("tool:privileged", "tool:referee")] == 2


def test_main_good_log(tmp_path, capsys):
    build_log(tmp_path / "a.jsonl")
    assert main([str(tmp_path / "a.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "chain: VERIFIED" in out and "tool:referee" in out
    assert "jane@example.com" not in out


def test_tampered_log_is_broken(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    build_log(path)
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["effect"] = "allow"
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert main([str(path)]) == 1
    assert "chain: BROKEN" in capsys.readouterr().out


def test_corrupt_log_is_broken(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    path.write_text("not json\n")
    assert main([str(path)]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_entries_without_mode_count_as_enforce(tmp_path):
    p = SecurityPipeline()
    p.guard(Action("llm", "chat", from_user("", source="u").provenance), "hi")
    assert summarize(list(p.audit))["by_sink_effect_mode"][("llm", "allow", "enforce")] == 1


def test_checkpoint_verification(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from datasec.crypto import LocalKeyProvider

    key = Fernet.generate_key()
    monkeypatch.setenv("DATASEC_KEY_K1", key.decode())
    path, cp = tmp_path / "a.jsonl", tmp_path / "a.checkpoint"
    log = AuditLog(path, signer=LocalKeyProvider({"k1": key}), checkpoint_path=cp)
    SecurityPipeline(audit=log).guard(Action("llm", "chat", from_user("", source="u").provenance), "hi")
    log.close()
    args = [str(path), "--checkpoint", str(cp), "--key-env", "DATASEC_KEY_K1"]
    assert main(args) == 0 and "checkpoint: VERIFIED" in capsys.readouterr().out
    path.write_text("")  # truncate everything after the checkpoint was written
    assert main(args) == 1 and "checkpoint: BROKEN" in capsys.readouterr().out


def test_control_characters_cannot_forge_report_lines(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    p = SecurityPipeline(audit=AuditLog(path))
    forged = Provenance(TrustLevel.EXTERNAL, "web\n\naudit: fake  entries: 0  chain: VERIFIED\x1b[31m")
    check(p, Action("tool:privileged", "pay", forged), "x", Mode.SHADOW)
    assert main([str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert sum(line.startswith("audit:") for line in lines) == 1  # the forged header stays inside one escaped line
    assert not any("\x1b" in line for line in lines)


def test_non_utf8_log_is_broken_not_a_traceback(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    path.write_bytes(b"\xff\xfe\x00garbage\n")
    assert main([str(path)]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_malformed_key_is_broken_not_a_traceback(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from datasec.crypto import LocalKeyProvider

    key = Fernet.generate_key()
    path, cp = tmp_path / "a.jsonl", tmp_path / "a.checkpoint"
    log = AuditLog(path, signer=LocalKeyProvider({"k1": key}), checkpoint_path=cp)
    SecurityPipeline(audit=log).guard(Action("llm", "chat", from_user("", source="u").provenance), "hi")
    log.close()
    monkeypatch.setenv("BADKEY", "not-a-fernet-key")
    assert main([str(path), "--checkpoint", str(cp), "--key-env", "BADKEY"]) == 1
    assert "checkpoint: BROKEN" in capsys.readouterr().out
