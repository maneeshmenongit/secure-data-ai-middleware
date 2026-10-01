"""Shared building blocks for red-team attacks against the DataSec core."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from datasec.pipeline import GuardResult, SecurityPipeline
from datasec.policy import Action, Effect

DEFENDED = frozenset({"blocked", "redacted", "detected", "bounded", "encrypted"})
EXPECTATIONS = DEFENDED | {"known_gap", "allowed"}  # "allowed" = must not over-block


@dataclass(frozen=True)
class Attack:
    id: str
    category: str
    owasp: str
    description: str
    run: Callable[[], str]
    expect: str
    requires: str | None = None  # importable module an optional attack depends on

    def __post_init__(self) -> None:
        if self.expect not in EXPECTATIONS:
            raise ValueError(f"{self.id}: unknown expectation {self.expect!r}")


def guard(
    sink: str, provenance: Any, payload: Any, name: str = "attack",
    pipeline: SecurityPipeline | None = None, **action_fields: Any,
) -> GuardResult:
    p = pipeline if pipeline is not None else SecurityPipeline()
    return p.guard(Action(sink, name, provenance, **action_fields), payload)


def outcome(result: GuardResult) -> str:
    return {Effect.DENY: "blocked", Effect.REDACT: "redacted", Effect.ALLOW: "allowed"}[
        result.decision.effect
    ]
