"""R3: move secret-labelled data out through egress sinks."""

from datasec.provenance import combine, from_user, internal
from redteam.common import Attack, guard, outcome

API_KEY = "sk-live-51H8xQ2eZvKZ"


def _key(value=API_KEY):
    return internal(value, source="vault:stripe", labels=("secret",))


def _secret_to(sink):
    def run():
        key = _key()
        return outcome(guard(sink, key.provenance, key.value))
    return run


def _secret_combined_with_clean():
    q = from_user("What's my balance?", source="user:1")
    key = _key()
    prompt = combine(q, key, source="prompt", value=f"{q.value} key={key.value}")
    return outcome(guard("llm", prompt.provenance, prompt.value))


def _secret_with_pii():
    # PII would normally REDACT; the secret must still win and DENY.
    key = _key(f"{API_KEY} owner jane@example.com")
    return outcome(guard("llm", key.provenance, key.value))


def _mixed_case_secret_label():
    key = internal(API_KEY, source="vault:stripe", labels=("Secret",))
    return outcome(guard("llm", key.provenance, key.value))


ATTACKS = [
    *[
        Attack(f"R3.{i}", "secret_exfiltration", "LLM02",
               f"send a secret-labelled value to {sink}", _secret_to(sink), "blocked")
        for i, sink in enumerate(["llm", "third_party", "http:response"], start=1)
    ],
    Attack("R3.4", "secret_exfiltration", "LLM02",
           "hide a secret inside a combine() with a harmless user question",
           _secret_combined_with_clean, "blocked"),
    Attack("R3.5", "secret_exfiltration", "LLM02",
           "pair a secret with PII hoping REDACT outranks DENY",
           _secret_with_pii, "blocked"),
    Attack("R3.6", "secret_exfiltration", "LLM02",
           "label the secret 'Secret' hoping the case-sensitive rule misses it",
           _mixed_case_secret_label, "blocked"),
]
