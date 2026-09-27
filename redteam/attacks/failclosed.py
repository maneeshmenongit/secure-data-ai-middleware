"""R5: probe every path that must fail closed."""

from datasec.pipeline import SecurityPipeline
from datasec.policy import PolicyEngine, Rule, default_rules
from datasec.provenance import from_user, internal
from redteam.common import Attack, guard, outcome

CLEAN = internal("Summarize today's release notes.", source="svc:notes")


def _sink(sink):
    return lambda: outcome(guard(sink, CLEAN.provenance, CLEAN.value))


def _bytes_payload():
    return outcome(guard("llm", from_user("", source="u").provenance, b"jane@example.com"))


def _raising_rule():
    def flaky(action):
        raise RuntimeError("policy backend down")

    p = SecurityPipeline(engine=PolicyEngine([*default_rules(), Rule("flaky", flaky)]))
    return outcome(guard("llm", CLEAN.provenance, CLEAN.value, pipeline=p))


def _deep_nesting():
    payload = "jane@example.com"
    for _ in range(10_000):
        payload = [payload]
    return outcome(guard("llm", CLEAN.provenance, payload))


def _missing_provenance():
    return outcome(guard("llm", None, CLEAN.value))


ATTACKS = [
    Attack("R5.1", "fail_closed", "LLM06", "upper-case sink 'LLM' to dodge egress rules", _sink("LLM"), "blocked"),
    Attack("R5.2", "fail_closed", "LLM06", "whitespace-padded sink ' llm'", _sink(" llm"), "blocked"),
    Attack("R5.3", "fail_closed", "LLM06", "made-up sink 'exfil'", _sink("exfil"), "blocked"),
    Attack("R5.4", "fail_closed", "LLM02", "PII smuggled as bytes the redactor can't read", _bytes_payload, "blocked"),
    Attack("R5.5", "fail_closed", "LLM06", "policy rule crashes mid-evaluation", _raising_rule, "blocked"),
    Attack("R5.6", "fail_closed", "LLM10", "10,000-deep nested payload to blow the stack", _deep_nesting, "blocked"),
    Attack("R5.7", "fail_closed", "LLM06", "action with no provenance at all", _missing_provenance, "blocked"),
]
