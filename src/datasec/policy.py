"""Actions, decisions, pluggable rules, and the DENY > REDACT > ALLOW engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable

from .provenance import Provenance, TrustLevel

EGRESS = frozenset({"llm", "third_party", "http:response"})
PRIVILEGED = frozenset({"tool:privileged", "third_party", "memory:write"})
KNOWN_SINKS = EGRESS | PRIVILEGED | {"tool:readonly"}


class Effect(Enum):
    ALLOW = "allow"
    REDACT = "redact"
    DENY = "deny"


@dataclass(frozen=True)
class Action:
    sink: str
    name: str
    provenance: Provenance


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    rule: str | None = None


@dataclass(frozen=True)
class Rule:
    name: str
    check: Callable[[Action], Decision | None]


_PRECEDENCE = (Effect.DENY, Effect.REDACT, Effect.ALLOW)


class PolicyEngine:
    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self.rules = tuple(rules)

    def evaluate(self, action: Action) -> Decision:
        decisions: list[Decision] = []
        for rule in self.rules:
            try:
                d = rule.check(action)
            except Exception as exc:
                # Only the type: the message may quote payload data.
                d = Decision(Effect.DENY, f"rule {rule.name} raised {type(exc).__name__}", rule.name)
            if d is None:
                continue
            if not isinstance(d, Decision):
                d = Decision(Effect.DENY, f"rule {rule.name} returned {type(d).__name__}", rule.name)
            elif not isinstance(d.effect, Effect):
                d = Decision(Effect.DENY, f"rule {rule.name} returned invalid effect", rule.name)
            decisions.append(d)
        for effect in _PRECEDENCE:
            for d in decisions:
                if d.effect is effect:
                    return d
        return Decision(Effect.ALLOW, "no rule objected", None)


def _no_untrusted_to_privileged(action: Action) -> Decision | None:
    if action.provenance.trust == TrustLevel.UNTRUSTED and action.sink in PRIVILEGED:
        return Decision(
            Effect.DENY, f"untrusted data cannot reach {action.sink}", "no_untrusted_to_privileged"
        )
    return None


def _never_leak_secrets(action: Action) -> Decision | None:
    if action.provenance.has("secret") and action.sink in EGRESS:
        return Decision(Effect.DENY, f"secret data cannot leave via {action.sink}", "never_leak_secrets")
    return None


def _redact_pii_on_egress(action: Action) -> Decision | None:
    if action.provenance.has("pii") and action.sink in EGRESS:
        return Decision(Effect.REDACT, f"pii redacted before {action.sink}", "redact_pii_on_egress")
    return None


def default_rules() -> list[Rule]:
    return [
        Rule("no_untrusted_to_privileged", _no_untrusted_to_privileged),
        Rule("never_leak_secrets", _never_leak_secrets),
        Rule("redact_pii_on_egress", _redact_pii_on_egress),
    ]
