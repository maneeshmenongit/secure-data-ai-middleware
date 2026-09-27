"""R4: rewrite history in the audit log file without being noticed."""

import json
import tempfile
from pathlib import Path

from datasec.audit import GENESIS, AuditLog, entry_hash
from datasec.errors import DataSecError
from datasec.pipeline import SecurityPipeline
from datasec.provenance import from_user, internal, untrusted
from redteam.common import Attack, guard


def _body(entry):
    return {k: v for k, v in entry.items() if k not in ("prev_hash", "hash")}


def _tamper(mutate, *, pin_head):
    """Record three decisions, let `mutate` rewrite the file, then verify it."""
    def run():
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            p = SecurityPipeline(audit=AuditLog(path))
            guard("tool:privileged", untrusted("", source="web").provenance, "wire money", pipeline=p)
            guard("llm", from_user("", source="u").provenance, "mail jane@example.com", pipeline=p)
            guard("llm", internal("", source="svc").provenance, "hello", pipeline=p)
            head = p.audit.head  # what an out-of-band anchor would have stored
            entries = mutate([json.loads(line) for line in path.read_text().splitlines()])
            path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
            try:
                ok = AuditLog.load(path).verify(expected_head=head if pin_head else None)
            except DataSecError:
                return "detected"
            return "undetected" if ok else "detected"
    return run


def _flip_denial(es):
    es[0]["effect"] = "allow"
    return es


def _delete_middle(es):
    del es[1]
    return es


def _swap(es):
    es[0], es[1] = es[1], es[0]
    return es


def _rehash_one(es):
    es[0]["effect"] = "allow"
    es[0]["hash"] = entry_hash(es[0]["prev_hash"], _body(es[0]))
    return es


def _rewrite_chain(es):
    es[0]["effect"] = "allow"
    prev = GENESIS
    for e in es:
        e["prev_hash"] = prev
        e["hash"] = entry_hash(prev, _body(e))
        prev = e["hash"]
    return es


def _truncate_tail(es):
    return es[:-1]


def _drop_field(es):
    del es[0]["reason"]
    return es


ATTACKS = [
    Attack("R4.1", "audit_tampering", "n/a", "flip a DENY to allow in place",
           _tamper(_flip_denial, pin_head=False), "detected"),
    Attack("R4.2", "audit_tampering", "n/a", "delete a middle entry",
           _tamper(_delete_middle, pin_head=False), "detected"),
    Attack("R4.3", "audit_tampering", "n/a", "reorder two entries",
           _tamper(_swap, pin_head=False), "detected"),
    Attack("R4.4", "audit_tampering", "n/a", "edit one entry and recompute its own hash",
           _tamper(_rehash_one, pin_head=False), "detected"),
    Attack("R4.5", "audit_tampering", "n/a", "rewrite the whole chain, head pinned out-of-band",
           _tamper(_rewrite_chain, pin_head=True), "detected"),
    Attack("R4.6", "audit_tampering", "n/a", "truncate the tail, head pinned out-of-band",
           _tamper(_truncate_tail, pin_head=True), "detected"),
    Attack("R4.7", "audit_tampering", "n/a", "remove a field from an entry",
           _tamper(_drop_field, pin_head=False), "detected"),
    Attack("R4g.1", "audit_tampering", "n/a", "truncate the tail with no pinned head",
           _tamper(_truncate_tail, pin_head=False), "known_gap"),
    Attack("R4g.2", "audit_tampering", "n/a", "rewrite the whole chain with no pinned head",
           _tamper(_rewrite_chain, pin_head=False), "known_gap"),
]
