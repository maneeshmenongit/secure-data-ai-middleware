"""R6: feed pathological 1 MB inputs to make the detectors blow up."""

import time

from datasec.provenance import from_user
from redteam.common import Attack, guard

LIMIT_SECONDS = 1.0
MB = 1_000_000


def _timed(payload):
    def run():
        start = time.perf_counter()
        guard("llm", from_user("", source="user:attacker").provenance, payload)
        return "bounded" if time.perf_counter() - start < LIMIT_SECONDS else "slow"
    return run


ATTACKS = [
    Attack("R6.1", "resource_abuse", "LLM10", "1 MB of email-local characters, no '@'",
           _timed("a" * MB), "bounded"),
    Attack("R6.2", "resource_abuse", "LLM10", "1 MB of 'a@' pairs",
           _timed("a@" * (MB // 2)), "bounded"),
    Attack("R6.3", "resource_abuse", "LLM10", "an email with a 1 MB dotted domain and no TLD",
           _timed("x@" + "a." * (MB // 2)), "bounded"),
    Attack("R6.4", "resource_abuse", "LLM10", "1 MB of digits",
           _timed("1" * MB), "bounded"),
    Attack("R6.5", "resource_abuse", "LLM10", "1 MB of space-separated digits",
           _timed("1 " * (MB // 2)), "bounded"),
    Attack("R6.6", "resource_abuse", "LLM10", "1 MB of dotted digits",
           _timed("1." * (MB // 2)), "bounded"),
    Attack("R6.7", "resource_abuse", "LLM10", "1 MB of phone-number prefixes",
           _timed("(555) " * (MB // 6)), "bounded"),
]
