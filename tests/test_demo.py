import demo
from datasec.policy import Effect


def test_demo_scenarios(capsys):
    out = demo.main()
    assert out["untrusted_to_privileged"].decision.effect is Effect.DENY
    assert out["pii_to_llm"].decision.effect is Effect.REDACT
    assert out["pii_to_llm"].payload == "Email me at [EMAIL]"
    assert out["clean_allow"].decision.effect is Effect.ALLOW
    assert out["audit_intact"] is True
    assert out["tamper_detected"] is True
    printed = capsys.readouterr().out
    assert "DENY" in printed and "REDACT" in printed and "ALLOW" in printed
    assert "jane.doe@example.com" not in printed
