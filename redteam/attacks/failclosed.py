"""R5: probe every path that must fail closed."""

from datasec.adapters.gate import Blocked, Mode, check
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action, PolicyEngine, Rule, default_rules
from datasec.provenance import from_user, internal, untrusted
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


def _self_reference():
    loop = []
    loop.append(loop)
    return outcome(guard("llm", CLEAN.provenance, loop))


def _shared_reference_blowup():
    node = []
    for _ in range(4):
        node = [node] * 1000  # 10^12 paths through 4,000 real objects
    return outcome(guard("llm", CLEAN.provenance, node))


def _shadow_on_egress():
    p = SecurityPipeline()
    try:
        out = check(p, Action("llm", "chat", from_user("", source="u").provenance), "mail jane@example.com", Mode.SHADOW)
    except ValueError:
        return "blocked"
    return "leaked" if "jane@example.com" in str(out) else "allowed"


def _caller_shadow_flag_on_egress():
    secret = internal("sk-test-FAKE", source="vault", labels="secret")
    r = SecurityPipeline().guard(Action("llm", "chat", secret.provenance, shadow=True), secret.value)
    return outcome(r)


def _enforce_gate_blocks():
    try:
        check(SecurityPipeline(), Action("tool:privileged", "pay", untrusted("", source="web:evil").provenance),
              "wire", Mode.ENFORCE)
    except Blocked:
        return "blocked"
    return "allowed"


def _shadow_on_misspelled_egress():
    for sink in ("LLM", " llm", "openai"):
        try:
            out = check(SecurityPipeline(), Action(sink, "chat", from_user("", source="u").provenance),
                        "mail jane@example.com", Mode.SHADOW)
        except ValueError:
            continue
        return "leaked" if "jane@example.com" in str(out) else "allowed"
    return "blocked"


def _blocked_error_echoes_pii():
    p = SecurityPipeline(engine=PolicyEngine(default_rules(egress_allowlist={"api.example"})))
    action = Action("third_party", "post", CLEAN.provenance, destination="evil.example/?email=jane@example.com")
    try:
        check(p, action, "hi", Mode.ENFORCE)
    except Blocked as exc:
        return "leaked" if "jane@example.com" in f"{exc} {exc.decision.reason}" else "blocked"
    return "allowed"


ATTACKS = [
    Attack("R5.1", "fail_closed", "LLM06", "upper-case sink 'LLM' to dodge egress rules", _sink("LLM"), "blocked"),
    Attack("R5.2", "fail_closed", "LLM06", "whitespace-padded sink ' llm'", _sink(" llm"), "blocked"),
    Attack("R5.3", "fail_closed", "LLM06", "made-up sink 'exfil'", _sink("exfil"), "blocked"),
    Attack("R5.4", "fail_closed", "LLM02", "PII smuggled as bytes the redactor can't read", _bytes_payload, "blocked"),
    Attack("R5.5", "fail_closed", "LLM06", "policy rule crashes mid-evaluation", _raising_rule, "blocked"),
    Attack("R5.6", "fail_closed", "LLM10", "10,000-deep nested payload to blow the stack", _deep_nesting, "blocked"),
    Attack("R5.7", "fail_closed", "LLM06", "action with no provenance at all", _missing_provenance, "blocked"),
    Attack("R5.8", "fail_closed", "LLM10", "self-referencing payload to loop the scanner forever",
           _self_reference, "blocked"),
    Attack("R5.9", "fail_closed", "LLM10", "shared-reference payload whose walk explodes combinatorially",
           _shared_reference_blowup, "blocked"),
    Attack("R5.10", "fail_closed", "LLM02", "ask the gate to shadow an egress sink (llm) to skip redaction",
           _shadow_on_egress, "blocked"),
    Attack("R5.11", "fail_closed", "LLM02", "pre-set Action.shadow on a secret headed to the llm",
           _caller_shadow_flag_on_egress, "blocked"),
    Attack("R5.12", "fail_closed", "LLM06", "untrusted data through the ENFORCE gate to a privileged tool",
           _enforce_gate_blocks, "blocked"),
    Attack("R5.13", "fail_closed", "LLM02", "shadow an egress sink by misspelling it ('LLM', ' llm', 'openai')",
           _shadow_on_misspelled_egress, "blocked"),
    Attack("R5.14", "fail_closed", "LLM02", "smuggle PII out through the text of a Blocked error",
           _blocked_error_echoes_pii, "blocked"),
]
