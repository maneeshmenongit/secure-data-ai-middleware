import pytest

from datasec.pipeline import SecurityPipeline
from webapp.rig import provenance_for, run
from webapp.scenarios import BY_ID, ORIGINS, SCENARIOS, SINKS
from webapp.sinks import Sinks


class Echo:
    def complete(self, prompt):
        return "Echo: " + prompt


class Boom:
    def complete(self, prompt):
        raise RuntimeError("network down")


def go(scenario_id, protection, llm=None):
    s = BY_ID[scenario_id]
    pipeline, sinks = SecurityPipeline(), Sinks()
    r = run(pipeline, sinks, llm or Echo(), text=s.text, origin=s.origin, sink=s.sink, protection=protection)
    return r, pipeline, sinks


def test_presets_are_well_formed():
    assert {s.id for s in SCENARIOS} == {"pii-chat", "injected-page", "tool-reply", "secret-response", "csv-rows"}
    for s in SCENARIOS:
        assert s.origin in ORIGINS and s.sink in SINKS and s.text and s.explain


@pytest.mark.parametrize("origin,trust,labels", [
    ("user", "USER", set()), ("web", "UNTRUSTED", set()),
    ("tool", "EXTERNAL", set()), ("vault", "INTERNAL", {"secret"}),
])
def test_provenance_for(origin, trust, labels):
    p = provenance_for(origin)
    assert p.trust.name == trust and set(p.labels) == labels


def test_pii_chat_protected_redacts_before_llm():
    r, _, _ = go("pii-chat", True)
    assert r.decision["effect"] == "redact"
    assert "4111 1111 1111 1111" not in r.delivered and "jane.doe@example.com" not in r.delivered
    assert "4111 1111 1111 1111" not in r.llm_reply and "[CREDIT_CARD]" in r.llm_reply


def test_pii_chat_unprotected_leaks_to_llm():
    r, _, _ = go("pii-chat", False)
    assert r.decision["effect"] == "bypass"
    assert r.delivered == BY_ID["pii-chat"].text
    assert "4111 1111 1111 1111" in r.llm_reply


@pytest.mark.parametrize("sid", ["injected-page", "tool-reply"])
def test_injection_blocked_when_protected(sid):
    r, _, sinks = go(sid, True)
    assert r.decision["effect"] == "deny"
    assert not r.reached_sink and r.delivered is None
    assert sinks.payment.calls == []


@pytest.mark.parametrize("sid", ["injected-page", "tool-reply"])
def test_injection_reaches_tool_when_unprotected(sid):
    r, _, sinks = go(sid, False)
    assert r.reached_sink and len(sinks.payment.calls) == 1


def test_secret_blocked_from_response():
    r, _, _ = go("secret-response", True)
    assert r.decision["effect"] == "deny" and r.delivered is None
    r, _, _ = go("secret-response", False)
    assert "sk-test-FAKE" in r.delivered


def test_csv_rows_redacted():
    r, _, _ = go("csv-rows", True)
    assert "angela@example.com" not in r.delivered and "555-123-4567" not in r.delivered


def test_bypass_is_audited_and_chain_verifies():
    r, pipeline, _ = go("pii-chat", False)
    entries = list(pipeline.audit)
    assert entries[-1].effect == "bypass" and entries[-1].reason == "protection off"
    assert r.audit["effect"] == "bypass"
    assert pipeline.audit.verify()


def test_bypass_audit_has_no_raw_pii():
    _, pipeline, _ = go("pii-chat", False)
    assert "jane.doe@example.com" not in str([e.body() for e in pipeline.audit])


def test_llm_exception_becomes_error_string():
    r, pipeline, _ = go("pii-chat", True, llm=Boom())
    assert r.llm_reply == "[llm error: RuntimeError]"
    assert len(pipeline.audit) >= 1 and pipeline.audit.verify()


def test_unknown_origin_or_sink_rejected():
    with pytest.raises(ValueError):
        run(SecurityPipeline(), Sinks(), Echo(), text="x", origin="martian", sink="llm", protection=True)
    with pytest.raises(ValueError):
        run(SecurityPipeline(), Sinks(), Echo(), text="x", origin="user", sink="exfil", protection=True)
