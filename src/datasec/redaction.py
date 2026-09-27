"""PII detection and one-way redaction over nested payloads (regex detectors)."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .errors import RedactionError, UnsupportedPayload

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
_SCALARS = (bool, int, float, type(None))


def normalize(text: str) -> str:
    """NFKC-fold look-alike characters and strip zero-width characters."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdecimal()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class Detector:
    label: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None


# Every pattern is anchored by a lookbehind and uses bounded repeats, so each
# start position does constant work and a scan is linear in the input size.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

DEFAULT_DETECTORS: tuple[Detector, ...] = (
    Detector(
        "EMAIL",
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"
            r"@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}"
        ),
    ),
    Detector("SSN", re.compile(r"(?<!\d)\d{3}[- ]?\d{2}[- ]?\d{4}(?!\d)")),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn_valid),
    Detector(
        "PHONE",
        re.compile(
            r"(?<![\d+])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
        ),
    ),
    Detector("IPV4", re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\.?\d)")),
)


@dataclass(frozen=True)
class RedactionResult:
    payload: Any
    found: dict[str, int]


class Redactor:
    def __init__(self, detectors: Iterable[Detector] = DEFAULT_DETECTORS) -> None:
        self.detectors = tuple(detectors)

    def scan(self, payload: Any) -> dict[str, int]:
        """Count PII findings without producing a redacted copy."""
        found: Counter[str] = Counter()
        self._walk(payload, found, strict_keys=False)
        return dict(found)

    def redact(self, payload: Any) -> RedactionResult:
        """Return a same-shaped copy with every finding replaced by [LABEL]."""
        found: Counter[str] = Counter()
        out = self._walk(payload, found, strict_keys=True)
        return RedactionResult(out, dict(found))

    def _walk(self, payload: Any, found: Counter[str], *, strict_keys: bool) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload, found)
        if isinstance(payload, _SCALARS):
            return payload
        if isinstance(payload, dict):
            out: dict[Any, Any] = {}
            for key, value in payload.items():
                if isinstance(key, str):
                    new_key = self._redact_text(key, found)
                elif isinstance(key, _SCALARS):
                    new_key = key
                else:
                    raise UnsupportedPayload(type(key).__name__)
                if strict_keys and new_key in out:
                    raise RedactionError("redacted dict keys collide")
                out[new_key] = self._walk(value, found, strict_keys=strict_keys)
            return out
        if isinstance(payload, list):
            return [self._walk(v, found, strict_keys=strict_keys) for v in payload]
        if isinstance(payload, tuple):
            return tuple(self._walk(v, found, strict_keys=strict_keys) for v in payload)
        raise UnsupportedPayload(type(payload).__name__)

    def _redact_text(self, text: str, found: Counter[str]) -> str:
        text = normalize(text)
        claimed = bytearray(len(text))
        spans: list[tuple[int, int, str]] = []
        for det in self.detectors:
            for m in det.pattern.finditer(text):
                start, end = m.span()
                if any(claimed[start:end]):
                    continue
                if det.validate is not None and not det.validate(m.group()):
                    continue
                claimed[start:end] = b"\x01" * (end - start)
                spans.append((start, end, det.label))
                found[det.label] += 1
        if not spans:
            return text
        spans.sort()
        parts: list[str] = []
        pos = 0
        for start, end, label in spans:
            parts.append(text[pos:start])
            parts.append(f"[{label}]")
            pos = end
        parts.append(text[pos:])
        return "".join(parts)
