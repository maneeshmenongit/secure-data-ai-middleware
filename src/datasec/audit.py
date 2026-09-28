"""Append-only, hash-chained, tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .errors import DataSecError

GENESIS = "0" * 64


def _canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def entry_hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    ts: str
    sink: str
    name: str
    effect: str
    reason: str
    rule: str | None
    trust: str
    source: str
    labels: list[str]
    tally: dict[str, int]
    prev_hash: str
    hash: str
    extra: dict[str, str] = field(default_factory=dict)

    def body(self) -> dict:
        data = asdict(self)
        del data["prev_hash"], data["hash"]
        if not data["extra"]:
            del data["extra"]  # keeps pre-Phase-2 entries hashing exactly as before
        return data


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        # Resume an existing file so a restart continues the same chain.
        if self._path is not None and self._path.exists():
            self._entries = _read_entries(self._path)
            if not self.verify():
                raise DataSecError(f"existing audit log {self._path} failed verification")

    def append(
        self, *, sink: str, name: str, effect: str, reason: str, rule: str | None,
        trust: str, source: str, labels: Iterable[str], tally: dict[str, int],
        extra: dict[str, str] | None = None,
    ) -> AuditEntry:
        body = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "sink": sink, "name": name, "effect": effect, "reason": reason, "rule": rule,
            "trust": trust, "source": source, "labels": sorted(labels), "tally": dict(tally),
        }
        if extra:
            body["extra"] = dict(extra)
        # Read-head, write, append must be atomic or concurrent guards fork the chain.
        with self._lock:
            prev = self.head
            entry = AuditEntry(**body, prev_hash=prev, hash=entry_hash(prev, body))
            # Persist first: if the write fails, memory stays consistent with disk.
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
                    f.flush()
            self._entries.append(entry)
        return entry

    @property
    def head(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS

    def verify(self, expected_head: str | None = None) -> bool:
        """Re-walk the chain. Pass a head stored elsewhere to also catch tail truncation."""
        prev = GENESIS
        for e in self._entries:
            if e.prev_hash != prev or entry_hash(prev, e.body()) != e.hash:
                return False
            prev = e.hash
        return expected_head is None or prev == expected_head

    @classmethod
    def load(cls, path: str | Path) -> AuditLog:
        """Read a log for inspection; it may fail verify(). To keep appending, use AuditLog(path)."""
        log = cls()
        log._entries = _read_entries(Path(path))
        return log

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


def _read_entries(path: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    with path.open(encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                entries.append(AuditEntry(**json.loads(line)))
            except (json.JSONDecodeError, TypeError) as exc:
                raise DataSecError(f"corrupt audit log at line {n}") from exc
    return entries
