import pytest

from datasec.adapters.gate import Blocked, Mode, check
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import from_user, internal, untrusted

USER = from_user("", source="user:1").provenance
WEB = untrusted("", source="web:evil").provenance
SVC = internal("", source="svc").provenance


def last(p):
    return list(p.audit)[-1]


def test_enforce_returns_redacted_payload():
    assert check(SecurityPipeline(), Action("llm", "chat", USER), "mail jane@example.com", Mode.ENFORCE) == "mail [EMAIL]"


def test_enforce_allow_returns_same_object():
    payload = {"q": "hi"}
    assert check(SecurityPipeline(), Action("llm", "chat", SVC), payload, Mode.ENFORCE) is payload


def test_enforce_deny_raises_blocked_with_decision():
    with pytest.raises(Blocked) as exc:
        check(SecurityPipeline(), Action("tool:privileged", "pay", WEB), "wire", Mode.ENFORCE)
    assert exc.value.decision.rule == "no_low_trust_to_privileged"


def test_shadow_returns_original_and_audits_real_decision():
    p = SecurityPipeline()
    payload = ["wire money"]
    assert check(p, Action("tool:privileged", "pay", WEB), payload, Mode.SHADOW) is payload
    assert last(p).effect == "deny" and last(p).extra == {"mode": "shadow"}


def test_shadow_memory_write_returns_original_even_with_pii():
    p = SecurityPipeline()
    payload = "remember jane@example.com"
    assert check(p, Action("memory:write", "note", USER), payload, Mode.SHADOW) is payload
    assert last(p).extra == {"mode": "shadow"}


@pytest.mark.parametrize("sink", ["llm", "third_party", "http:response"])
def test_shadow_on_egress_is_refused(sink):
    p = SecurityPipeline()
    with pytest.raises(ValueError):
        check(p, Action(sink, "x", USER), "jane@example.com", Mode.SHADOW)
    assert len(p.audit) == 0


def test_enforce_strips_caller_shadow_flag():
    p = SecurityPipeline()
    check(p, Action("llm", "chat", SVC, shadow=True), "hi", Mode.ENFORCE)
    assert "mode" not in last(p).extra


def test_mode_must_be_a_mode():
    with pytest.raises(TypeError):
        check(SecurityPipeline(), Action("llm", "chat", SVC), "hi", "shadow")
