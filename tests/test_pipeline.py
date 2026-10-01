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
    assert r.decision.rule == "no_low_trust_to_privileged"
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
    assert r.decision.reason == "payload too deep"


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


def test_rule_labels_reason_and_rule_name_are_redacted_in_audit(tmp_path):
    from datasec.policy import Decision, Rule, default_rules
    from datasec.provenance import Provenance, TrustLevel

    path = tmp_path / "audit.jsonl"
    leaky = Rule("rule for john@example.com",
                 lambda a: Decision(Effect.DENY, f"blocked {a.name}", "rule for john@example.com"))
    p = SecurityPipeline(engine=PolicyEngine([*default_rules(), leaky]), audit=AuditLog(path))
    prov = Provenance(TrustLevel.USER, "s", {"john@example.com"})
    p.guard(Action("tool:readonly", "email john@example.com", prov), "hi")
    assert "john@example.com" not in path.read_text()


@pytest.mark.parametrize(
    "action",
    [None, "llm", __import__("types").SimpleNamespace(sink="llm", name="x", provenance=USER)],
)
def test_invalid_action_denied_and_audited(action):
    p = SecurityPipeline()
    r = p.guard(action, "jane@example.com")
    assert not r.allowed and r.payload is None
    assert r.decision.reason == "invalid action"
    assert len(p.audit) == 1


class NoneEngine(PolicyEngine):
    def evaluate(self, action):
        return None


def test_engine_returning_garbage_denies():
    p = SecurityPipeline(engine=NoneEngine())
    r = p.guard(Action("llm", "chat", SVC), "hi")
    assert not r.allowed
    assert r.decision.reason == "policy failed"


def test_numeric_card_redacted_when_action_opts_in():
    r = SecurityPipeline().guard(
        Action("llm", "chat", USER, scan_integers=True), {"card": 4111111111111111}
    )
    assert r.payload == {"card": "[CREDIT_CARD]"}


def test_numeric_id_not_corrupted_by_default():
    payload = {"order_id": 4111111111111111}
    r = SecurityPipeline().guard(Action("llm", "chat", USER), payload)
    assert r.decision.effect is Effect.ALLOW
    assert r.payload is payload


def test_action_default_does_not_disable_pipeline_integer_scanning():
    p = SecurityPipeline(redactor=Redactor(scan_integers=True))
    r = p.guard(Action("llm", "chat", USER), {"card": 4111111111111111})
    assert r.payload == {"card": "[CREDIT_CARD]"}


def test_mixed_case_secret_label_still_denied_on_egress():
    prov = internal("", source="vault", labels="Secret").provenance
    r = SecurityPipeline().guard(Action("llm", "chat", prov), "sk-test-FAKE")
    assert not r.allowed
    assert r.decision.rule == "never_leak_secrets"


def test_mixed_case_pii_label_still_redacts_on_egress():
    from datasec.provenance import Provenance, TrustLevel

    prov = Provenance(TrustLevel.USER, "u", {"PII"})
    r = SecurityPipeline().guard(Action("llm", "chat", prov), "Jane Doe, Elm St")
    assert r.decision.rule == "redact_pii_on_egress"


def test_payload_over_byte_cap_denied_and_audited():
    p = SecurityPipeline(max_bytes=10)
    assert p.guard(Action("llm", "chat", SVC), "x" * 10).allowed
    r = p.guard(Action("llm", "chat", SVC), "x" * 11)
    assert not r.allowed
    assert r.decision.reason == "payload too large"
    assert last(p).effect == "deny"


def test_bytes_are_counted_as_utf8():
    p = SecurityPipeline(max_bytes=4)
    assert p.guard(Action("llm", "chat", SVC), "éé").allowed
    assert p.guard(Action("llm", "chat", SVC), "ééé").decision.reason == "payload too large"


def test_nesting_past_max_depth_denied():
    p = SecurityPipeline(max_depth=3)
    assert p.guard(Action("llm", "chat", SVC), [[["x"]]]).allowed
    assert p.guard(Action("llm", "chat", SVC), [[[["x"]]]]).decision.reason == "payload too deep"


def test_self_referencing_payload_denied():
    loop = []
    loop.append(loop)
    r = SecurityPipeline().guard(Action("llm", "chat", SVC), loop)
    assert not r.allowed
    assert r.decision.reason == "payload too deep"


@pytest.mark.parametrize("kwargs", [{"max_bytes": 0}, {"max_depth": 0}])
def test_invalid_caps_rejected(kwargs):
    with pytest.raises(ValueError):
        SecurityPipeline(**kwargs)


def _secret(value="sk-test-FAKE-123"):
    return internal(value, source="vault", labels="secret")


def test_secret_memory_write_is_sealed():
    from datasec.crypto import LocalKeyProvider, Sealed, unseal

    kp = LocalKeyProvider()
    p = SecurityPipeline(key_provider=kp)
    s = _secret()
    r = p.guard(Action("memory:write", "remember", s.provenance), {"key": s.value})
    assert r.allowed
    assert isinstance(r.payload, Sealed)
    assert "sk-test-FAKE-123" not in r.payload.token
    assert unseal(kp, r.payload) == {"key": "sk-test-FAKE-123"}
    assert last(p).extra == {"encryption": "key:k1"}


def test_secret_memory_write_without_provider_degrades_and_is_audited(caplog):
    p = SecurityPipeline()
    s = _secret()
    with caplog.at_level("WARNING", logger="datasec"):
        r1 = p.guard(Action("memory:write", "remember", s.provenance), s.value)
        p.guard(Action("memory:write", "remember", s.provenance), s.value)
    assert r1.allowed and r1.payload == "sk-test-FAKE-123"
    assert last(p).extra == {"encryption": "unavailable"}
    assert sum("no KeyProvider" in m for m in caplog.messages) == 1


def test_non_secret_memory_write_not_sealed():
    from datasec.crypto import LocalKeyProvider

    p = SecurityPipeline(key_provider=LocalKeyProvider())
    r = p.guard(Action("memory:write", "remember", SVC), "plain note")
    assert r.payload == "plain note"
    assert last(p).extra == {}


def test_encryption_failure_denies():
    class BrokenProvider:
        def current_key_id(self):
            return "k1"

        def encrypt(self, plaintext, *, key_id=None):
            raise RuntimeError("kms down")

        def decrypt(self, ciphertext, *, key_id):
            raise RuntimeError("kms down")

    p = SecurityPipeline(key_provider=BrokenProvider())
    r = p.guard(Action("memory:write", "remember", _secret().provenance), "sk-test-FAKE-123")
    assert not r.allowed and r.payload is None
    assert r.decision.reason == "encryption failed"
    assert last(p).extra == {"encryption": "failed"}


def test_shared_reference_payload_is_bounded():
    import time

    node = []
    for _ in range(4):
        node = [node] * 1000
    start = time.perf_counter()
    r = SecurityPipeline().guard(Action("llm", "chat", SVC), node)
    assert time.perf_counter() - start < 2.0
    assert r.decision.reason == "payload too large"


@pytest.mark.parametrize("payload", [b"x" * 2_000_000, 10 ** 1_200_000], ids=["bytes", "huge_int"])
def test_bytes_and_huge_ints_count_toward_cap(payload):
    r = SecurityPipeline().guard(Action("llm", "chat", SVC), payload)
    assert r.decision.reason == "payload too large"


def test_third_party_without_destination_denied():
    r = SecurityPipeline().guard(Action("third_party", "post", SVC), "report")
    assert not r.allowed
    assert r.decision.rule == "egress_allowlist"


def test_fullwidth_secret_label_denied_on_egress():
    prov = internal("", source="vault", labels="ＳＥＣＲＥＴ").provenance
    r = SecurityPipeline().guard(Action("llm", "chat", prov), "x")
    assert r.decision.rule == "never_leak_secrets"


def test_egress_destination_recorded_in_audit():
    from datasec.policy import default_rules

    p = SecurityPipeline(engine=PolicyEngine(default_rules(egress_allowlist={"api.example"})))
    p.guard(Action("third_party", "post", SVC, destination="api.example"), "hi")
    assert last(p).extra == {"destination": "api.example"}


def test_destination_pii_is_redacted_in_audit():
    p = SecurityPipeline()
    p.guard(Action("third_party", "post", SVC, destination="jane@example.com"), "hi")
    assert last(p).extra == {"destination": "[EMAIL]"}


class SpyNER(Redactor):
    """Stands in for an NER-capable redactor: records every call and its ner flag."""

    ner_capable = True

    def __init__(self):
        super().__init__()
        self.calls = []

    def scan(self, payload, *, scan_integers=None, ner=True):
        self.calls.append(("scan", payload, ner))
        return super().scan(payload, scan_integers=scan_integers)

    def redact(self, payload, *, scan_integers=None, ner=True):
        self.calls.append(("redact", payload, ner))
        return super().redact(payload, scan_integers=scan_integers)


@pytest.mark.parametrize(
    "sink,expected",
    [("llm", True), ("http:response", True), ("tool:readonly", False), ("memory:write", False)],
)
def test_ner_flag_follows_egress(sink, expected):
    spy = SpyNER()
    SecurityPipeline(redactor=spy).guard(Action(sink, "op", USER), "payload-text")
    assert [ner for kind, payload, ner in spy.calls if payload == "payload-text"] == [expected]


def test_metadata_ner_only_for_caller_text():
    spy = SpyNER()
    prov = from_user("", source="user:Jane Doe").provenance
    SecurityPipeline(redactor=spy).guard(
        Action("tool:readonly", "lookup Jane", prov, destination="api.example"), "x"
    )
    ner_texts = {payload for kind, payload, ner in spy.calls if kind == "redact" and ner}
    assert ner_texts == {"lookup Jane", "user:Jane Doe", "api.example"}


def test_plain_redactor_gets_no_ner_kwarg():
    class Legacy(Redactor):
        def scan(self, payload):
            return super().scan(payload)

        def redact(self, payload):
            return super().redact(payload)

    r = SecurityPipeline(redactor=Legacy()).guard(Action("llm", "chat", USER), "mail jane@example.com")
    assert r.payload == "mail [EMAIL]"
