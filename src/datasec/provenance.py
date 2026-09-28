"""The provenance / taint model: trust travels with the data."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Generic, Iterable, TypeVar

T = TypeVar("T")
U = TypeVar("U")


class TrustLevel(IntEnum):
    """Ordered trust scale; lower is less trusted, so min() picks the weakest."""

    UNTRUSTED = 0
    EXTERNAL = 1
    USER = 2
    INTERNAL = 3
    TRUSTED = 4


@dataclass(frozen=True)
class Provenance:
    trust: TrustLevel
    source: str
    labels: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "trust", TrustLevel(self.trust))
        object.__setattr__(self, "labels", _normalize_labels(self.labels))

    def with_labels(self, *labels: str) -> Provenance:
        return Provenance(self.trust, self.source, self.labels | frozenset(labels))

    def has(self, label: str) -> bool:
        return label.strip().lower() in self.labels


def _normalize_labels(labels: Iterable[str] | str) -> frozenset[str]:
    """One spelling per label, so 'PII' can't slip past a rule checking 'pii'."""
    if isinstance(labels, str):
        labels = (labels,)
    out = set()
    for label in labels:
        if not isinstance(label, str):
            raise TypeError(f"label must be str, got {type(label).__name__}")
        norm = label.strip().lower()
        if not norm:
            raise ValueError("label must not be empty")
        out.add(norm)
    return frozenset(out)


@dataclass(frozen=True)
class Tainted(Generic[T]):
    value: T
    provenance: Provenance

    def map(self, fn: Callable[[T], U]) -> Tainted[U]:
        """Single-input transform: trust and labels are unchanged."""
        return Tainted(fn(self.value), self.provenance)


def combine(*inputs: Tainted[Any], source: str = "derived", value: Any = None) -> Tainted[Any]:
    """The only merge path: weakest trust wins, labels are sticky."""
    if not inputs:
        raise ValueError("combine() needs at least one input")
    trust = min(t.provenance.trust for t in inputs)
    labels = frozenset().union(*(t.provenance.labels for t in inputs))
    return Tainted(value, Provenance(trust, source, labels))


def untrusted(value: T, source: str, labels: Iterable[str] | str = ()) -> Tainted[T]:
    return Tainted(value, Provenance(TrustLevel.UNTRUSTED, source, labels))


def from_user(value: T, source: str, labels: Iterable[str] | str = ()) -> Tainted[T]:
    return Tainted(value, Provenance(TrustLevel.USER, source, labels))


def internal(value: T, source: str, labels: Iterable[str] | str = ()) -> Tainted[T]:
    return Tainted(value, Provenance(TrustLevel.INTERNAL, source, labels))
