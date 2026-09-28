"""SecurityPipeline.guard(): the single call every adapter uses."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from .audit import AuditLog
from .errors import DataSecError, UnsupportedPayload
from .policy import KNOWN_SINKS, Action, Decision, Effect, PolicyEngine, default_rules
from .provenance import Provenance
from .redaction import Redactor


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    payload: Any
    decision: Decision


def _deny(reason: str, rule: str | None = None) -> Decision:
    return Decision(Effect.DENY, reason, rule)


def _over_cap(payload: Any, max_bytes: int, max_depth: int) -> str | None:
    """Size and depth check before any detector runs. Iterative, so no recursion limit,
    and depth-bounded, so a self-referencing payload stops instead of looping."""
    size = 0
    stack: list[tuple[Any, int]] = [(payload, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, str):
            size += len(item.encode("utf-8", "surrogatepass"))
        elif isinstance(item, (dict, list, tuple)):
            if depth + 1 > max_depth:
                return "payload too deep"
            children = [c for kv in item.items() for c in kv] if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
        else:
            size += 8
        if size > max_bytes:
            return "payload too large"
    return None


class SecurityPipeline:
    def __init__(
        self,
        engine: PolicyEngine | None = None,
        redactor: Redactor | None = None,
        audit: AuditLog | None = None,
        *,
        max_bytes: int = 1_000_000,
        max_depth: int = 200,
    ) -> None:
        if max_bytes < 1 or max_depth < 1:
            raise ValueError("max_bytes and max_depth must be >= 1")
        # `is not None`, not `or`: an empty AuditLog is falsy (it has __len__).
        self.engine = engine if engine is not None else PolicyEngine(default_rules())
        self.redactor = redactor if redactor is not None else Redactor()
        self.audit = audit if audit is not None else AuditLog()
        self.max_bytes = max_bytes
        self.max_depth = max_depth

    def guard(self, action: Action, payload: Any) -> GuardResult:
        if isinstance(action, Action):
            decision, out, action, tally = self._decide(action, payload)
        else:
            decision, out, action, tally = _deny("invalid action"), None, Action("", "", None), {}
        self._record(action, decision, tally)
        return GuardResult(decision.effect is not Effect.DENY, out, decision)

    def _decide(self, action: Action, payload: Any) -> tuple[Decision, Any, Action, dict[str, int]]:
        if not isinstance(action.sink, str) or action.sink not in KNOWN_SINKS:
            return _deny("unknown sink"), None, action, {}
        if not isinstance(action.provenance, Provenance):
            return _deny("missing provenance"), None, action, {}
        over = _over_cap(payload, self.max_bytes, self.max_depth)
        if over:
            return _deny(over), None, action, {}
        # Only pass the flag when set, so custom redactors with the Phase 1 signature still work.
        ints = {"scan_integers": True} if action.scan_integers else {}
        try:
            tally = self.redactor.scan(payload, **ints)
        except (UnsupportedPayload, RecursionError):
            return _deny("unsupported payload"), None, action, {}
        except Exception:
            return _deny("scan failed"), None, action, {}
        if tally:
            action = replace(action, provenance=action.provenance.with_labels("pii"))
        try:
            decision = self.engine.evaluate(action)
            if not isinstance(decision, Decision) or not isinstance(decision.effect, Effect):
                raise TypeError("engine returned an invalid decision")
        except Exception:
            return _deny("policy failed"), None, action, tally
        if decision.effect is Effect.DENY:
            return decision, None, action, tally
        if decision.effect is Effect.REDACT:
            try:
                return decision, self.redactor.redact(payload, **ints).payload, action, tally
            except Exception:
                return _deny("redaction failed", decision.rule), None, action, tally
        return decision, payload, action, tally

    def _record(self, action: Action, decision: Decision, tally: dict[str, int]) -> None:
        prov = action.provenance if isinstance(action.provenance, Provenance) else None
        try:
            self.audit.append(
                sink=self._safe(action.sink),
                name=self._safe(action.name),
                effect=decision.effect.value,
                reason=self._safe(decision.reason),
                rule=self._safe(decision.rule) if decision.rule is not None else None,
                trust=prov.trust.name if prov else "UNKNOWN",
                source=self._safe(prov.source) if prov else "",
                labels=sorted(self._safe(label) for label in prov.labels) if prov else [],
                tally=tally,
            )
        except Exception as exc:
            raise DataSecError("audit append failed") from exc

    def _safe(self, value: Any) -> str:
        """Caller-supplied metadata (names, labels, custom rule text) can carry PII; redact it."""
        try:
            return self.redactor.redact(str(value)).payload
        except Exception:
            return "[UNREDACTABLE]"
