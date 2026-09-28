"""Append-only, hash-chained, tamper-evident audit log."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .errors import DataSecError

GENESIS = "0" * 64
CHECKPOINT_TAG = b"datasec-checkpoint/v1\n"


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


@dataclass(frozen=True)
class SignedCheckpoint:
    """Out-of-band anchor for the chain head. The token is the {head, count, ts}
    triple encrypted with a KeyProvider key; Fernet tokens are authenticated,
    so an edited checkpoint file fails is_valid()."""

    head: str
    count: int
    ts: str
    key_id: str
    token: str

    def claims(self) -> dict:
        return {"head": self.head, "count": self.count, "ts": self.ts}

    def is_valid(self, verifier: Any) -> bool:
        try:
            plaintext = verifier.decrypt(self.token.encode("ascii"), key_id=self.key_id)
            if not plaintext.startswith(CHECKPOINT_TAG):
                return False
            signed = json.loads(plaintext[len(CHECKPOINT_TAG):])
        except Exception:
            return False
        return signed == self.claims()

    def save(self, path: str | Path) -> None:
        path = Path(path)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(asdict(self), sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written checkpoint

    @classmethod
    def read(cls, path: str | Path) -> SignedCheckpoint:
        try:
            return cls(**json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise DataSecError(f"corrupt audit checkpoint {path}") from exc


class AuditLog:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        signer: Any = None,
        checkpoint_path: str | Path | None = None,
        checkpoint_every: int = 100,
    ) -> None:
        if (signer is None) != (checkpoint_path is None):
            raise ValueError("signer and checkpoint_path must be given together")
        if signer is not None and path is None:
            raise ValueError("checkpointing needs a file-backed log (path)")
        self._entries: list[AuditEntry] = []
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._signer = signer
        self._checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self._checkpoint_every = checkpoint_every
        # Resume an existing file so a restart continues the same chain; refuse a
        # file that fails verification, including against its last checkpoint.
        if self._path is not None and self._path.exists():
            self._entries = _read_entries(self._path)
        cp = None
        if self._checkpoint_path is not None:
            if self._checkpoint_path.exists():
                cp = SignedCheckpoint.read(self._checkpoint_path)
            elif self._entries:
                # A checkpointed log always has a checkpoint (one is written at creation),
                # so a missing file means it was removed: fail closed.
                raise DataSecError(f"audit checkpoint {self._checkpoint_path} is missing")
        if not self.verify(checkpoint=cp, verifier=signer):
            raise DataSecError(f"existing audit log {self._path} failed verification")
        if self._checkpoint_path is not None and cp is None:
            self.checkpoint(signer).save(self._checkpoint_path)

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
            if self._signer is not None and len(self._entries) % self._checkpoint_every == 0:
                self.checkpoint(self._signer).save(self._checkpoint_path)
        return entry

    def checkpoint(self, signer: Any) -> SignedCheckpoint:
        with self._lock:
            claims = {
                "head": self.head,
                "count": len(self._entries),
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            key_id = signer.current_key_id()
            plaintext = CHECKPOINT_TAG + _canonical(claims).encode("utf-8")
            token = signer.encrypt(plaintext, key_id=key_id).decode("ascii")
            return SignedCheckpoint(**claims, key_id=key_id, token=token)

    def close(self) -> None:
        """Write a final checkpoint on clean shutdown (no-op without a signer)."""
        if self._signer is not None:
            self.checkpoint(self._signer).save(self._checkpoint_path)

    @property
    def head(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS

    def verify(
        self, expected_head: str | None = None, *, checkpoint: SignedCheckpoint | None = None, verifier: Any = None,
    ) -> bool:
        """Re-walk the chain. A pinned head or a signed checkpoint also catches
        truncation and whole-chain rewrites, which the chain alone cannot."""
        prev = GENESIS
        for e in self._entries:
            if e.prev_hash != prev or entry_hash(prev, e.body()) != e.hash:
                return False
            prev = e.hash
        if checkpoint is not None:
            if verifier is None or not checkpoint.is_valid(verifier):
                return False
            if checkpoint.count > len(self._entries):
                return False
            anchor = self._entries[checkpoint.count - 1].hash if checkpoint.count else GENESIS
            if anchor != checkpoint.head:
                return False
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
