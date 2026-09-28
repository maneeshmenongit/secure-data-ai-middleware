"""PII detection and one-way redaction over nested payloads (regex detectors)."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .errors import RedactionError, UnsupportedPayload

_SCALARS = (bool, int, float, type(None))


class _Fold(dict):
    """Lazy str.translate table: drop invisible characters, map every dash to '-'."""

    def __missing__(self, cp: int) -> int | str | None:
        category = unicodedata.category(chr(cp))
        if category == "Cf" or cp == 0x034F or 0xFE00 <= cp <= 0xFE0F:
            value: int | str | None = None
        elif category == "Pd":
            value = "-"
        else:
            value = cp
        self[cp] = value
        return value


_FOLD = _Fold()


def normalize(text: str) -> str:
    """NFKC-fold look-alikes, strip invisible format characters, unify dashes."""
    return unicodedata.normalize("NFKC", text).translate(_FOLD)


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
    # Dots only as a matched pair (123.45.6789), so decimals like 123.456789 don't match.
    Detector("SSN", re.compile(r"(?<!\d)\d{3}(?:[- ]?\d{2}[- ]?|\.\d{2}\.)\d{4}(?!\d)")),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn_valid),
    # Exact card layouts, for when the loose match above swallowed a neighbouring
    # number (CVV, reference) and failed Luhn. Each is linear, like the rest.
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{13,19}(?!\d)"), luhn_valid),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{4}(?:[ -]\d{4}){3}(?!\d)"), luhn_valid),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{4}[ -]\d{6}[ -]\d{5}(?!\d)"), luhn_valid),
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
    def __init__(
        self,
        detectors: Iterable[Detector] = DEFAULT_DETECTORS,
        *,
        scan_integers: bool = False,
        integer_fields: Iterable[str] | None = None,
    ) -> None:
        self.detectors = tuple(detectors)
        self.scan_integers = scan_integers
        self.integer_fields = (
            None if integer_fields is None else frozenset(f.strip().lower() for f in integer_fields)
        )

    def scan(self, payload: Any, *, scan_integers: bool | None = None) -> dict[str, int]:
        """Count PII findings without producing a redacted copy."""
        found: Counter[str] = Counter()
        self._walk(payload, found, strict_keys=False, ints=self._ints(scan_integers))
        return dict(found)

    def redact(self, payload: Any, *, scan_integers: bool | None = None) -> RedactionResult:
        """Return a same-shaped copy with every finding replaced by [LABEL]."""
        found: Counter[str] = Counter()
        out = self._walk(payload, found, strict_keys=True, ints=self._ints(scan_integers))
        return RedactionResult(out, dict(found))

    def _ints(self, override: bool | None) -> bool:
        return self.scan_integers if override is None else override

    def _walk(
        self, payload: Any, found: Counter[str], *, strict_keys: bool, ints: bool, field: str | None = None,
    ) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload, found)
        if isinstance(payload, _SCALARS):
            return self._redact_int(payload, found) if self._int_in_scope(ints, field) else payload
        if isinstance(payload, dict):
            out: dict[Any, Any] = {}
            for key, value in payload.items():
                if isinstance(key, str):
                    new_key = self._redact_text(key, found)
                elif isinstance(key, _SCALARS):
                    new_key = self._redact_int(key, found) if self._int_in_scope(ints, None) else key
                else:
                    raise UnsupportedPayload(type(key).__name__)
                if strict_keys and new_key in out:
                    raise RedactionError("redacted dict keys collide")
                child_field = key if isinstance(key, str) else None
                out[new_key] = self._walk(value, found, strict_keys=strict_keys, ints=ints, field=child_field)
            return out
        if isinstance(payload, list):
            return [self._walk(v, found, strict_keys=strict_keys, ints=ints, field=field) for v in payload]
        if isinstance(payload, tuple):
            return tuple(self._walk(v, found, strict_keys=strict_keys, ints=ints, field=field) for v in payload)
        raise UnsupportedPayload(type(payload).__name__)

    def _int_in_scope(self, ints: bool, field: str | None) -> bool:
        """Integers are scanned only on opt-in, and only under declared fields if any are set."""
        if not ints:
            return False
        if self.integer_fields is None:
            return True
        return field is not None and field.strip().lower() in self.integer_fields

    def _redact_int(self, value: Any, found: Counter[str]) -> Any:
        """Numeric JSON fields can hold card numbers or SSNs; scan their digits."""
        if type(value) is not int:
            return value
        text = str(value)
        redacted = self._redact_text(text, found)
        return value if redacted == text else redacted

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
