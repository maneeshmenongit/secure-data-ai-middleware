import pytest

from datasec.audit import AuditLog
from datasec.errors import DataSecError
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action, Effect, PolicyEngine
from datasec.provenance import from_user, internal, untrusted
from datasec.redaction import Redactor

USER = from_user("", source="user:req-1").provenance
SVC = internal("", source="svc").provenance
WEB = untrusted("", source="web:evil.example").provenance


def last(p):
    return list(p.audit)[-1]


def test_clean_internal_to_llm_allows_same_object():
    p = SecurityPipeline()
    payload = {"q": "summarize release notes"}
    r = p.guard(Action("llm", "chat", SVC), payload)
    assert r.allowed
    assert r.payload is payload
    assert r.decision.effect is Effect.ALLOW
    assert len(p.audit) == 1
    assert last(p).effect == "allow"


def test_user_pii_to_llm_is_redacted_and_labelled():
    p = SecurityPipeline()
    r = p.guard(Action("llm", "chat", USER), "mail jane@example.com")
    assert r.allowed
    assert r.payload == "mail [EMAIL]"
    assert r.decision.rule == "redact_pii_on_egress"
    e = last(p)
    assert e.effect == "redact"
    assert e.tally == {"EMAIL": 1}
    assert "pii" in e.labels


def test_pii_to_readonly_tool_passes_unchanged():
    p = SecurityPipeline()
    r = p.guard(Action("tool:readonly", "lookup", USER), "jane@example.com")
    assert r.allowed and r.payload == "jane@example.com"
    assert last(p).tally == {"EMAIL": 1}


def test_untrusted_to_privileged_denied():
    p = SecurityPipeline()
    r = p.guard(Action("tool:privileged", "pay", WEB), "wire money")
    assert not r.allowed
    assert r.payload is None
    assert r.decision.rule == "no_untrusted_to_privileged"
    assert last(p).effect == "deny"


def test_secret_with_pii_to_llm_denied():
    p = SecurityPipeline()
    secret = internal("", source="vault", labels=("secret",)).provenance
    r = p.guard(Action("llm", "chat", secret), "key sk-1 owner jane@example.com")
    assert not r.allowed and r.payload is None
    assert r.decision.rule == "never_leak_secrets"


@pytest.mark.parametrize("sink", ["LLM", " llm", "exfil", ""])
def test_unknown_sink_denied_and_audited(sink):
    p = SecurityPipeline()
    r = p.guard(Action(sink, "x", SVC), "hi")
    assert not r.allowed
    assert r.decision.reason == "unknown sink"
    assert len(p.audit) == 1


def test_missing_provenance_denied():
    p = SecurityPipeline()
    r = p.guard(Action("llm", "x", None), "hi")
    assert not r.allowed
    assert r.decision.reason == "missing provenance"
    assert last(p).trust == "UNKNOWN"


@pytest.mark.parametrize("payload", [b"jane@example.com", {"k": object()}])
def test_unsupported_payload_denied(payload):
    p = SecurityPipeline()
    r = p.guard(Action("llm", "chat", USER), payload)
    assert not r.allowed
    assert r.decision.reason == "unsupported payload"


def test_deeply_nested_payload_denied():
    payload = "x"
    for _ in range(10_000):
        payload = [payload]
    p = SecurityPipeline()
    r = p.guard(Action("llm", "chat", USER), payload)
    assert not r.allowed
    assert r.decision.reason == "unsupported payload"


def test_redacted_key_collision_denied():
    p = SecurityPipeline()
    r = p.guard(Action("llm", "chat", USER), {"a@x.com": 1, "b@x.com": 2})
    assert not r.allowed
    assert r.decision.reason == "redaction failed"


class ExplodingRedact(Redactor):
    def redact(self, payload):
        raise RuntimeError("boom")


class ExplodingScan(Redactor):
    def scan(self, payload):
        raise RuntimeError("boom")


class ExplodingEngine(PolicyEngine):
    def evaluate(self, action):
        raise RuntimeError("boom")


class BrokenAudit(AuditLog):
    def append(self, **kwargs):
        raise OSError("disk full")


def test_redaction_failure_denies():
    p = SecurityPipeline(redactor=ExplodingRedact())
    r = p.guard(Action("llm", "chat", USER), "jane@example.com")
    assert not r.allowed and r.payload is None
    assert r.decision.reason == "redaction failed"
    assert last(p).effect == "deny"


def test_scan_failure_denies():
    p = SecurityPipeline(redactor=ExplodingScan())
    r = p.guard(Action("llm", "chat", SVC), "hi")
    assert not r.allowed
    assert r.decision.reason == "scan failed"


def test_policy_failure_denies():
    p = SecurityPipeline(engine=ExplodingEngine())
    r = p.guard(Action("llm", "chat", SVC), "hi")
    assert not r.allowed
    assert r.decision.reason == "policy failed"


def test_audit_failure_raises():
    p = SecurityPipeline(audit=BrokenAudit())
    with pytest.raises(DataSecError):
        p.guard(Action("llm", "chat", SVC), "hi")


def test_empty_audit_log_passed_in_is_used():
    log = AuditLog()
    p = SecurityPipeline(audit=log)
    p.guard(Action("llm", "chat", SVC), "hi")
    assert len(log) == 1


def test_empty_engine_passed_in_is_used():
    p = SecurityPipeline(engine=PolicyEngine())
    assert p.guard(Action("tool:privileged", "pay", WEB), "x").allowed


def test_callers_action_is_not_mutated():
    action = Action("llm", "chat", USER)
    SecurityPipeline().guard(action, "jane@example.com")
    assert not action.provenance.has("pii")


def test_pii_in_source_and_name_is_redacted_in_audit():
    p = SecurityPipeline()
    prov = from_user("", source="user:jane@example.com").provenance
    p.guard(Action("llm", "lookup jane@example.com", prov), "hi")
    e = last(p)
    assert e.source == "user:[EMAIL]"
    assert e.name == "lookup [EMAIL]"


def test_raw_pii_never_reaches_audit_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    p = SecurityPipeline(audit=AuditLog(path))
    raw = ["jane@example.com", "123-45-6789", "4111 1111 1111 1111", "(555) 123-4567", "10.0.0.1"]
    user = from_user("", source="user:jane@example.com").provenance
    for sink in ["llm", "tool:readonly", "tool:privileged", "exfil"]:
        for s in raw:
            p.guard(Action(sink, f"op {s}", user), {"body": s, s: [s]})
    text = path.read_text()
    for s in raw:
        assert s not in text
    assert AuditLog.load(path).verify(expected_head=p.audit.head)
