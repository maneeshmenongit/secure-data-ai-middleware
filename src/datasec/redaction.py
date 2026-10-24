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
    group: int = 0  # redact only this capture group (keyword context stays readable)
    # Scan a copy with UUID-shaped ids and long decimal fractions hidden (see _mask_host_numbers).
    # Off by default, so custom detectors see the text as written.
    skip_ids_and_fractions: bool = False


# Every pattern is anchored by a lookbehind and uses bounded repeats, so each
# start position does constant work and a scan is linear in the input size.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_US_STATES = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|"
    "NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR"
)
# Words that follow "I am" / "I'm" but are not names.
_NOT_NAMES = frozenset(
    "Happy Sorry Here Not Fine Good Glad Ready Sure Interested Available Back In On The A An Looking "
    "Writing Calling Trying Going So Very Also Still Just Currently Afraid Unable Able New Done".split()
)


def _is_name(match: str) -> bool:
    return match.split()[0] not in _NOT_NAMES


def _is_routable_ipv4(match: str) -> bool:
    """Loopback (127/8) and the unspecified address identify no one; hosts write them in
    their own instructions. Private ranges still map an internal network, so they stay."""
    return not (match.split(".", 1)[0] == "127" or match == "0.0.0.0")


# UUID-shaped ids (8-4-4-4-12 hex). Their digit groups trip SSN/PHONE/card patterns, so
# their hex is hidden from those detectors (same length, so offsets hold). Only tokens with
# a hex letter count: an all-digit dashed run is a number and is still scanned. A leading
# "-" is allowed only after another id or a non-digit ("mem-<id>", "<id>-<id>"), so a
# dashed SSN/phone/card glued to an id ("555-123-4567abcd-…") keeps its last group.
_UUID = re.compile(
    r"(?:(?<![0-9A-Fa-f-])|(?<=[0-9A-Fa-f]{12}-)|(?<=[^0-9-]-))"
    r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
_HEX = re.compile(r"[0-9A-Fa-f]")
_HEX_LETTER = re.compile(r"[A-Fa-f]")
# The digits of a decimal fraction long enough to hold an SSN, phone or card (9+): a cost or
# a ratio. Only a bare run of 9+ digits after "<digit>." is hidden, so "2.123-45-6789" (list
# numbering) is still scanned; whatever follows that run is not checked (known gaps R2g.8-10).
_FRACTION = re.compile(r"(?<![\d.])\d{1,20}\.(\d{9,30})(?!\d|\.\d)")


def _mask_ids(text: str) -> str:
    def mask(m: re.Match[str]) -> str:
        token = m.group()
        return _HEX.sub("x", token) if _HEX_LETTER.search(token) else token

    return _UUID.sub(mask, text)


def _mask_host_numbers(text: str) -> str:
    """Ids and long fractions that hosts write themselves, hidden from the digit detectors."""
    def mask(m: re.Match[str]) -> str:
        start, end = m.span(1)
        return m.group()[: start - m.start()] + "x" * (end - start)

    return _FRACTION.sub(mask, _mask_ids(text))


DEFAULT_DETECTORS: tuple[Detector, ...] = (
    # Self-introductions: "my name is Maneesh", "I'm Priya Raman". The name must be capitalised.
    Detector(
        "PERSON",
        re.compile(
            r"(?i:\b(?:my name is|my name's|i am|i'm|i\u2019m|call me|name[ \t]{0,2}:))"
            r"[ \t]{1,3}([A-Z][a-z]{1,30}(?:[ \t][A-Z][a-z]{1,30})?)\b"
        ),
        _is_name, group=1,
    ),
    # Account / routing / IBAN numbers, recognised by the keyword in front of them.
    Detector(
        "ACCOUNT_NUMBER",
        re.compile(
            r"(?i:\b(?:account|acct|a/c|routing|iban)\b(?:[ \t]{0,3}(?:number|num|no\.?|#|id))?"
            r"(?:[ \t]{1,3}[a-z]{1,12}){0,4}?"  # "for the bill" between keyword and number
            r"(?:[ \t]{0,3}(?:is|:|=))?)[ \t]{0,3}(\d[\d -]{4,24}\d)(?!\d)"
        ),
        group=1,
    ),
    # Street address: house number, up to 4 words, a street suffix. Abbreviations match in any
    # case; full words must be capitalised so "a 5 minute drive" is not an address.
    Detector(
        "ADDRESS",
        re.compile(
            r"(?<![\w.])\d{1,6}[ \t]{1,3}(?:[A-Za-z][A-Za-z.'-]{0,29}[ \t]{1,3}){0,4}?"
            r"(?:(?i:st|ave|rd|blvd|ln|dr|pkwy|hwy|ct|ter)\b\.?"
            r"|(?:Street|Avenue|Road|Boulevard|Lane|Drive|Parkway|Highway|Court|Terrace|Way|Place)\b)"
        ),
    ),
    # US state code + ZIP ("NJ 07922", "CA 94107-1234").
    Detector("ZIP_CODE", re.compile(rf"\b(?:{_US_STATES})[ \t]{{1,3}}\d{{5}}(?:-\d{{4}})?(?!\d)")),
    # Coordinates: a "lat, long" pair, or a precise decimal after a geo keyword.
    Detector(
        "GEO_COORDINATE",
        re.compile(r"(?<![\d.])-?\d{1,3}\.\d{3,12}[ \t]{0,3},[ \t]{0,3}-?\d{1,3}\.\d{3,12}(?!\.?\d)"),
    ),
    Detector(
        "GEO_COORDINATE",
        re.compile(
            r"(?i:\b(?:lat(?:itude)?|lon(?:g(?:itude)?)?|lng|coord(?:inate)?s?|gps)\b)"
            r"[^\d\n-]{0,20}(-?\d{1,3}\.\d{3,12})(?!\.?\d)"
        ),
        group=1,
    ),
    Detector(
        "EMAIL",
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"
            r"@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}"
        ),
    ),
    # Dots only as a matched pair (123.45.6789), so decimals like 123.456789 don't match.
    Detector("SSN", re.compile(r"(?<!\d)\d{3}(?:[- ]?\d{2}[- ]?|\.\d{2}\.)\d{4}(?!\d)"),
             skip_ids_and_fractions=True),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn_valid,
             skip_ids_and_fractions=True),
    # Exact card layouts, for when the loose match above swallowed a neighbouring
    # number (CVV, reference) and failed Luhn. Each is linear, like the rest.
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{13,19}(?!\d)"), luhn_valid,
             skip_ids_and_fractions=True),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{4}(?:[ -]\d{4}){3}(?!\d)"), luhn_valid,
             skip_ids_and_fractions=True),
    Detector("CREDIT_CARD", re.compile(r"(?<!\d)\d{4}[ -]\d{6}[ -]\d{5}(?!\d)"), luhn_valid,
             skip_ids_and_fractions=True),
    Detector(
        "PHONE",
        re.compile(
            r"(?<![\d+])(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
        ),
        skip_ids_and_fractions=True,
    ),
    Detector(
        "IPV4", re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\.?\d)"), _is_routable_ipv4
    ),
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
        if integer_fields is not None:
            if isinstance(integer_fields, str):
                raise TypeError("integer_fields must be a collection of strings, not a bare str")
            if not scan_integers:
                raise ValueError("integer_fields only takes effect with scan_integers=True")
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
        self, payload: Any, found: Counter[str], *, strict_keys: bool, ints: bool,
        field: str | None = None, ner: bool = False,
    ) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload, found, **({"ner": True} if ner else {}))
        if isinstance(payload, _SCALARS):
            return self._redact_int(payload, found) if self._int_in_scope(ints, field) else payload
        if isinstance(payload, dict):
            out: dict[Any, Any] = {}
            for key, value in payload.items():
                if isinstance(key, str):
                    new_key = self._redact_text(key, found, **({"ner": True} if ner else {}))
                elif isinstance(key, _SCALARS):
                    new_key = self._redact_int(key, found) if self._int_in_scope(ints, None) else key
                else:
                    raise UnsupportedPayload(type(key).__name__)
                if strict_keys and new_key in out:
                    raise RedactionError("redacted dict keys collide")
                # Scope is inherited: everything nested under a declared field stays in scope.
                declared = (
                    self.integer_fields is not None
                    and isinstance(key, str)
                    and key.strip().lower() in self.integer_fields
                )
                child_field = key if declared else field
                out[new_key] = self._walk(
                    value, found, strict_keys=strict_keys, ints=ints, field=child_field, ner=ner
                )
            return out
        if isinstance(payload, list):
            return [
                self._walk(v, found, strict_keys=strict_keys, ints=ints, field=field, ner=ner) for v in payload
            ]
        if isinstance(payload, tuple):
            return tuple(
                self._walk(v, found, strict_keys=strict_keys, ints=ints, field=field, ner=ner) for v in payload
            )
        raise UnsupportedPayload(type(payload).__name__)

    def _int_in_scope(self, ints: bool, field: str | None) -> bool:
        """Integers are scanned only on opt-in, and only under declared fields if any are set."""
        if not ints:
            return False
        # `field` is the nearest declared ancestor key, or None outside any declared field.
        return self.integer_fields is None or field is not None

    def _redact_int(self, value: Any, found: Counter[str]) -> Any:
        """Numeric JSON fields can hold card numbers or SSNs; scan their digits."""
        if type(value) is not int:
            return value
        text = str(value)
        redacted = self._redact_text(text, found)
        return value if redacted == text else redacted

    def _redact_text(self, text: str, found: Counter[str], *, ner: bool = False) -> str:
        return link_locations(self._redact_spans(text, found)[0], found)

    def _redact_spans(self, text: str, found: Counter[str]) -> tuple[str, list[tuple[int, int]]]:
        """Regex redaction. Also returns where each placeholder sits in the output, so a
        later pass knows exactly which brackets are ours (not user-written look-alikes)."""
        text = normalize(text)
        masked: str | None = None
        claimed = bytearray(len(text))
        spans: list[tuple[int, int, str]] = []
        for det in self.detectors:
            if getattr(det, "skip_ids_and_fractions", False):
                masked = _mask_host_numbers(text) if masked is None else masked
                scanned = masked
            else:
                scanned = text
            for m in det.pattern.finditer(scanned):
                start, end = m.span(det.group)
                if any(claimed[start:end]):
                    continue
                # Validators see the real text, never the masked copy.
                if det.validate is not None and not det.validate(text[start:end]):
                    continue
                claimed[start:end] = b"\x01" * (end - start)
                spans.append((start, end, det.label))
                found[det.label] += 1
        if not spans:
            return text, []
        spans.sort()
        parts: list[str] = []
        placed: list[tuple[int, int]] = []
        pos = out = 0
        for start, end, label in spans:
            parts.append(text[pos:start])
            out += start - pos
            placeholder = f"[{label}]"
            parts.append(placeholder)
            placed.append((out, out + len(placeholder)))
            out += len(placeholder)
            pos = end
        parts.append(text[pos:])
        return "".join(parts), placed


# ---- Location linking -------------------------------------------------------------------
# Location is all-or-nothing: once a string reveals any location, the leftover fragments
# (a bare ZIP, a state code, precise coordinates, a house number) re-identify it, so they go
# too, and adjacent pieces merge into one [ADDRESS] so even the shape doesn't leak. Strings
# with no location keep the conservative rules above.
_LOCATION_PLACEHOLDER = re.compile(r"\[(?:LOCATION|ADDRESS|ZIP_CODE|GEO_COORDINATE)\]")
_LINKED = (
    ("ADDRESS", re.compile(r"(?<![\d.])\d{1,6}(?=[ \t]{1,3}\[(?:LOCATION|ADDRESS)\])")),
    ("ZIP_CODE", re.compile(r"(?<![\d.])\d{5}(?:-\d{4})?(?!\.?\d)")),
    ("GEO_COORDINATE", re.compile(r"(?<![\d.])-?\d{1,3}\.\d{4,12}(?!\.?\d)")),
    ("LOCATION", re.compile(rf"\b(?:{_US_STATES})\b")),
)
_ADDRESS_RUN = re.compile(
    r"\[(?:LOCATION|ADDRESS|ZIP_CODE)\](?:[ \t]{0,3},?[ \t]{0,3}\[(?:LOCATION|ADDRESS|ZIP_CODE)\])+"
)


def link_locations(text: str, found: Counter[str]) -> str:
    if not _LOCATION_PLACEHOLDER.search(text):
        return text
    for label, pattern in _LINKED:
        # Match on the id-masked copy, replace in the real text: ids keep their digits.
        spans = [m.span() for m in pattern.finditer(_mask_ids(text))]
        if spans:
            found[label] += len(spans)
            parts, pos = [], 0
            for start, end in spans:
                parts += [text[pos:start], f"[{label}]"]
                pos = end
            text = "".join(parts) + text[pos:]
    return _ADDRESS_RUN.sub("[ADDRESS]", text)

