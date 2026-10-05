"""One call for adapters: enforce a decision, or audit it in shadow mode without acting on it."""

from __future__ import annotations

from dataclasses import replace
from enum import Enum
from typing import Any

from ..errors import DataSecError
from ..pipeline import SecurityPipeline
from ..policy import SHADOWABLE, Action, Decision
from ..provenance import Provenance


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
    shadowed, nor are unknown sinks or secret memory writes.
    """
    if not isinstance(mode, Mode):
        raise TypeError(f"mode must be a Mode, got {type(mode).__name__}")
    if mode is Mode.SHADOW:
        # Allowlist, not blocklist: "LLM", " llm" or an unknown sink must never be observe-only.
        if not (isinstance(action.sink, str) and action.sink in SHADOWABLE):
            raise ValueError("shadow mode is only for tool:privileged and memory:write; other sinks are always enforced")
        if (action.sink == "memory:write" and isinstance(action.provenance, Provenance)
                and action.provenance.has("secret")):
            raise ValueError("secret memory writes are always enforced (sealed at rest)")
        pipeline.guard(replace(action, shadow=True), payload)
        return payload
    result = pipeline.guard(replace(action, shadow=False), payload)
    if not result.allowed:
        # Hosts persist error text (Via stores str(exc)): carry only the redacted reason.
        d = result.decision
        raise Blocked(Decision(d.effect, pipeline._safe(d.reason, ner=True), d.rule))
    return result.payload
