"""Runs one scenario through the pipeline, or around it when protection is off."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Protocol

from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import Provenance, Tainted, TrustLevel, combine, from_user, internal, untrusted

from .scenarios import ORIGINS, SINKS
from .sinks import Sinks


class Completer(Protocol):
    def complete(self, prompt: str) -> str: ...


@dataclass
class RunResult:
    sent: str
    origin: str
    sink: str
    protection: bool
    decision: dict
    delivered: Any
    reached_sink: bool
    llm_reply: str | None
    audit: dict


def provenance_for(origin: str) -> Provenance:
    if origin == "user":
        return from_user("", source="user:demo").provenance
    if origin == "web":
        return untrusted("", source="web:demo-page").provenance
    if origin == "tool":
        return Provenance(TrustLevel.EXTERNAL, "api:weather")
    if origin == "vault":
        return internal("", source="vault:demo", labels="secret").provenance
    raise ValueError(f"unknown origin {origin!r}")


def _complete(llm: Completer, prompt: str) -> str:
    try:
        return llm.complete(prompt)
    except Exception as exc:  # the demo must survive any backend failure; never echo details
        return f"[llm error: {type(exc).__name__}]"


def _audit_bypass(pipeline: SecurityPipeline, sink: str, name: str, prov: Provenance) -> None:
    """Protection OFF skips guard() but must still leave a (redacted) audit trail."""
    pipeline.audit.append(
        sink=sink,
        name=pipeline._safe(name, ner=True),
        effect="bypass",
        reason="protection off",
        rule=None,
        trust=prov.trust.name,
        source=pipeline._safe(prov.source, ner=True),
        labels=sorted(prov.labels),
        tally={},
    )


def run(
    pipeline: SecurityPipeline, sinks: Sinks, llm: Completer, *,
    text: str, origin: str, sink: str, protection: bool, name: str | None = None,
) -> RunResult:
    if origin not in ORIGINS:
        raise ValueError(f"unknown origin {origin!r}")
    if sink not in SINKS:
        raise ValueError(f"unknown sink {sink!r}")
    name = name or f"demo:{sink}"
    prov = provenance_for(origin)
    llm_reply: str | None = None

    if protection:
        result = pipeline.guard(Action(sink, name, prov), text)
        decision = {
            "effect": result.decision.effect.value,
            "reason": result.decision.reason,
            "rule": result.decision.rule,
        }
        delivered = result.payload if result.allowed else None
    else:
        _audit_bypass(pipeline, sink, name, prov)
        decision = {"effect": "bypass", "reason": "protection off", "rule": None}
        delivered = text

    reached = delivered is not None
    if reached and sink == "tool:privileged":
        sinks.payment.call(delivered)
    elif reached and sink == "llm":
        raw_reply = _complete(llm, delivered)
        if protection:
            # The reply carries everything the model saw: guard it on the way out too.
            reply_prov = combine(Tainted(None, prov), source="llm:reply").provenance
            out = pipeline.guard(Action("http:response", "llm-reply", reply_prov), raw_reply)
            llm_reply = out.payload if out.allowed else f"[reply blocked: {out.decision.reason}]"
        else:
            llm_reply = raw_reply

    audit = asdict(list(pipeline.audit)[-1]) if len(pipeline.audit) else {}
    return RunResult(text, origin, sink, protection, decision, delivered, reached, llm_reply, audit)
