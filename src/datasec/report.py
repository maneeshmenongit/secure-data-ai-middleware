"""Summarise a DataSec audit log: python -m datasec.report <audit.jsonl> [--checkpoint P --key-env NAME]

Verifies the chain (and a signed checkpoint when given) before summarising, and exits 1 when
the log is broken. Prints only the fields the log stores; the log never holds payloads.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from typing import Iterable

from .audit import AuditEntry, AuditLog, SignedCheckpoint
from .errors import DataSecError


def _mode(e: AuditEntry) -> str:
    return e.extra.get("mode", "enforce")  # entries from before shadow mode are enforce


def summarize(entries: Iterable[AuditEntry]) -> dict:
    by: Counter = Counter()
    reasons: Counter = Counter()
    shadow: Counter = Counter()
    for e in entries:
        by[(e.sink, e.effect, _mode(e))] += 1
        if e.effect == "deny":
            reasons[(e.reason, e.rule)] += 1
            if _mode(e) == "shadow":
                shadow[(e.sink, e.source)] += 1
    return {"by_sink_effect_mode": by, "deny_reasons": reasons, "shadow_denials": shadow}


def _checkpoint_status(log: AuditLog, cp_path: str, key_env: str) -> bool:
    from .crypto import LocalKeyProvider  # needs the crypto extra

    cp = SignedCheckpoint.read(cp_path)
    key = os.environ.get(key_env)
    if not key:
        raise DataSecError(f"env var {key_env} is not set")
    return log.verify(checkpoint=cp, verifier=LocalKeyProvider({cp.key_id: key.encode()}))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m datasec.report", description="Summarise a DataSec audit log")
    ap.add_argument("log")
    ap.add_argument("--checkpoint")
    ap.add_argument("--key-env")
    args = ap.parse_args(argv)
    try:
        log = AuditLog.load(args.log)
    except (DataSecError, OSError) as exc:
        print(f"audit: {args.log}\nchain: BROKEN ({type(exc).__name__}: unreadable log)")
        return 1
    ok = log.verify()
    line = f"audit: {args.log}  entries: {len(log)}  chain: {'VERIFIED' if ok else 'BROKEN'}"
    if args.checkpoint:
        try:
            cp_ok = _checkpoint_status(log, args.checkpoint, args.key_env or "DATASEC_KEY_K1")
        except DataSecError as exc:
            cp_ok = False
            line += f"  ({exc})"
        ok = ok and cp_ok
        line += f"  checkpoint: {'VERIFIED' if cp_ok else 'BROKEN'}"
    print(line)
    s = summarize(log)
    print("\ndecisions (sink / effect / mode):")
    for (sink, effect, mode), n in sorted(s["by_sink_effect_mode"].items()):
        print(f"  {sink:18} {effect:7} {mode:8} {n}")
    print("\ntop deny reasons:")
    for (reason, rule), n in s["deny_reasons"].most_common(10):
        print(f"  {n:4}  {reason}  [{rule}]")
    print("\nshadow denials (sink / source) — false-positive candidates to review:")
    for (sink, source), n in s["shadow_denials"].most_common():
        print(f"  {sink:18} {source:24} {n}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
