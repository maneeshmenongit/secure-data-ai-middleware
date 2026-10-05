"""One call for adapters: enforce a decision, or audit it in shadow mode without acting on it."""

from __future__ import annotations

from dataclasses import replace
from enum import Enum
from typing import Any

from ..errors import DataSecError
from ..pipeline import SecurityPipeline
from ..policy import EGRESS, Action, Decision


class Mode(Enum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


class Blocked(DataSecError):
    """An ENFORCE check denied the action; `.decision` says why."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"blocked by datasec: {decision.reason}")
        self.decision = decision


def check(pipeline: SecurityPipeline, action: Action, payload: Any, mode: Mode) -> Any:
    """Return the payload the caller should use.

    ENFORCE: ALLOW/REDACT -> the guarded payload; DENY -> raise Blocked.
    SHADOW: audit the real decision (marked mode=shadow) and return the ORIGINAL payload,
    so behaviour is unchanged while the decision is observed. Egress sinks are never
    shadowed: PII redaction and secret blocking can't be switched off.
    """
    if not isinstance(mode, Mode):
        raise TypeError(f"mode must be a Mode, got {type(mode).__name__}")
    if mode is Mode.SHADOW:
        if action.sink in EGRESS:
            raise ValueError(f"egress sink {action.sink!r} is always enforced; shadow refused")
        pipeline.guard(replace(action, shadow=True), payload)
        return payload
    result = pipeline.guard(replace(action, shadow=False), payload)
    if not result.allowed:
        raise Blocked(result.decision)
    return result.payload
