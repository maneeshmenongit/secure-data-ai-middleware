import pytest

from datasec.policy import (
    EGRESS,
    KNOWN_SINKS,
    PRIVILEGED,
    Action,
    Decision,
    Effect,
    PolicyEngine,
    Rule,
    default_rules,
)
from datasec.provenance import Provenance, TrustLevel

ENGINE = PolicyEngine(default_rules())


def act(sink, trust=TrustLevel.USER, labels=()):
    return Action(sink, "op", Provenance(trust, "test", labels))


def test_sink_groups():
    assert EGRESS == {"llm", "third_party", "http:response"}
    assert PRIVILEGED == {"tool:privileged", "third_party", "memory:write"}
    assert KNOWN_SINKS == EGRESS | PRIVILEGED | {"tool:readonly"}


def test_empty_engine_allows():
    assert PolicyEngine().evaluate(act("llm")) == Decision(Effect.ALLOW, "no rule objected", None)


@pytest.mark.parametrize("sink", sorted(PRIVILEGED))
def test_untrusted_to_privileged_denied(sink):
    d = ENGINE.evaluate(act(sink, TrustLevel.UNTRUSTED))
    assert d.effect is Effect.DENY
    assert d.rule == "no_low_trust_to_privileged"


def test_untrusted_to_readonly_tool_allowed():
    assert ENGINE.evaluate(act("tool:readonly", TrustLevel.UNTRUSTED)).effect is Effect.ALLOW


@pytest.mark.parametrize("sink", sorted(PRIVILEGED))
def test_external_to_privileged_denied(sink):
    d = ENGINE.evaluate(act(sink, TrustLevel.EXTERNAL))
    assert d.effect is Effect.DENY
    assert d.rule == "no_low_trust_to_privileged"
    assert d.reason == f"external data cannot reach {sink}"


def test_user_to_privileged_allowed():
    assert ENGINE.evaluate(act("tool:privileged", TrustLevel.USER)).effect is Effect.ALLOW


def test_allowlisted_external_source_reaches_privileged():
    engine = PolicyEngine(default_rules(privileged_source_allowlist={"api:stripe-verified"}))
    action = Action("tool:privileged", "pay", Provenance(TrustLevel.EXTERNAL, "api:stripe-verified"))
    assert engine.evaluate(action).effect is Effect.ALLOW


def test_allowlist_never_exempts_untrusted():
    engine = PolicyEngine(default_rules(privileged_source_allowlist={"web:evil"}))
    action = Action("tool:privileged", "pay", Provenance(TrustLevel.UNTRUSTED, "web:evil"))
    assert engine.evaluate(action).effect is Effect.DENY


@pytest.mark.parametrize("sink", sorted(EGRESS))
def test_secret_on_egress_denied(sink):
    d = ENGINE.evaluate(act(sink, TrustLevel.INTERNAL, ("secret",)))
    assert d.effect is Effect.DENY
    assert d.rule == "never_leak_secrets"


def test_secret_to_memory_write_allowed():
    assert ENGINE.evaluate(act("memory:write", TrustLevel.INTERNAL, ("secret",))).effect is Effect.ALLOW


@pytest.mark.parametrize("sink", sorted(EGRESS))
def test_pii_on_egress_redacted(sink):
    d = ENGINE.evaluate(act(sink, TrustLevel.USER, ("pii",)))
    assert d.effect is Effect.REDACT
    assert d.rule == "redact_pii_on_egress"


def test_pii_off_egress_allowed():
    assert ENGINE.evaluate(act("tool:readonly", TrustLevel.USER, ("pii",))).effect is Effect.ALLOW


def test_deny_beats_redact():
    d = ENGINE.evaluate(act("llm", TrustLevel.INTERNAL, ("secret", "pii")))
    assert d.effect is Effect.DENY
    assert d.rule == "never_leak_secrets"


def test_first_rule_wins_within_same_effect():
    r1 = Rule("first", lambda a: Decision(Effect.DENY, "one", "first"))
    r2 = Rule("second", lambda a: Decision(Effect.DENY, "two", "second"))
    assert PolicyEngine([r1, r2]).evaluate(act("llm")).rule == "first"


def test_raising_rule_denies_without_leaking_message():
    def boom(action):
        raise ValueError("jane@example.com")

    d = PolicyEngine([Rule("boom", boom)]).evaluate(act("llm"))
    assert d == Decision(Effect.DENY, "rule boom raised ValueError", "boom")


def test_rule_returning_garbage_denies():
    d = PolicyEngine([Rule("bad", lambda a: "allow")]).evaluate(act("llm"))
    assert d == Decision(Effect.DENY, "rule bad returned str", "bad")


def test_decision_with_non_effect_denies():
    bad = Rule("bad", lambda a: Decision("deny", "x", "bad"))
    d = PolicyEngine([*default_rules(), bad]).evaluate(act("llm"))
    assert d == Decision(Effect.DENY, "rule bad returned invalid effect", "bad")
