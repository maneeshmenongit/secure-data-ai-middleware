"""Actions, decisions, pluggable rules, and the DENY > REDACT > ALLOW engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable

from .provenance import Provenance, TrustLevel

EGRESS = frozenset({"llm", "third_party", "http:response"})
PRIVILEGED = frozenset({"tool:privileged", "third_party", "memory:write"})
KNOWN_SINKS = EGRESS | PRIVILEGED | {"tool:readonly"}

# Sources exempt from the low-trust rule. EXTERNAL only: UNTRUSTED is never exempt.
PRIVILEGED_SOURCE_ALLOWLIST: frozenset[str] = frozenset()

# Hosts egress sinks may name as a destination. Empty = deny every named destination.
EGRESS_ALLOWLIST: frozenset[str] = frozenset()


class Effect(Enum):
    ALLOW = "allow"
    REDACT = "redact"
    DENY = "deny"


@dataclass(frozen=True)
class Action:
    sink: str
    name: str
    provenance: Provenance
    destination: str | None = None
    scan_integers: bool = False


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


def _no_low_trust_to_privileged(source_allowlist: Iterable[str]) -> Callable[[Action], Decision | None]:
    allowed = frozenset(source_allowlist)

    def check(action: Action) -> Decision | None:
        trust = action.provenance.trust
        if action.sink not in PRIVILEGED or trust > TrustLevel.EXTERNAL:
            return None
        if trust == TrustLevel.EXTERNAL and action.provenance.source in allowed:
            return None
        return Decision(
            Effect.DENY, f"{trust.name.lower()} data cannot reach {action.sink}", "no_low_trust_to_privileged"
        )

    return check


def _never_leak_secrets(action: Action) -> Decision | None:
    if action.provenance.has("secret") and action.sink in EGRESS:
        return Decision(Effect.DENY, f"secret data cannot leave via {action.sink}", "never_leak_secrets")
    return None


def _egress_allowlist(allowlist: Iterable[str]) -> Callable[[Action], Decision | None]:
    allowed = frozenset(host.strip().lower() for host in allowlist)

    def check(action: Action) -> Decision | None:
        if action.sink not in EGRESS:
            return None
        if action.destination is None:
            # llm / http:response go to fixed, configured endpoints; a third party must be named.
            if action.sink == "third_party":
                return Decision(Effect.DENY, "third_party egress needs a destination", "egress_allowlist")
            return None
        # A non-str destination raises here; the engine turns that into DENY.
        if action.destination.strip().lower() in allowed:
            return None
        return Decision(Effect.DENY, f"egress to {action.destination} not allowlisted", "egress_allowlist")

    return check


def _redact_pii_on_egress(action: Action) -> Decision | None:
    if action.provenance.has("pii") and action.sink in EGRESS:
        return Decision(Effect.REDACT, f"pii redacted before {action.sink}", "redact_pii_on_egress")
    return None


def default_rules(
    *,
    privileged_source_allowlist: Iterable[str] = PRIVILEGED_SOURCE_ALLOWLIST,
    egress_allowlist: Iterable[str] = EGRESS_ALLOWLIST,
) -> list[Rule]:
    return [
        Rule("no_low_trust_to_privileged", _no_low_trust_to_privileged(privileged_source_allowlist)),
        Rule("never_leak_secrets", _never_leak_secrets),
        Rule("egress_allowlist", _egress_allowlist(egress_allowlist)),
        Rule("redact_pii_on_egress", _redact_pii_on_egress),
    ]
