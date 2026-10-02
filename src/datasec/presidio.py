"""Optional NER pass for people and places, behind the Redactor interface.

Install: pip install 'datasec[presidio]' && python -m spacy download en_core_web_lg
"""

from __future__ import annotations

from collections import Counter
from contextvars import ContextVar
from typing import Any, Iterable, Iterator

from .errors import DataSecError, RedactionError
from .redaction import DEFAULT_DETECTORS, Detector, RedactionResult, Redactor, link_locations

INSTALL_HINT = "pip install 'datasec[presidio]' && python -m spacy download {model}"


class _Budget:
    """Total NER work allowed for one scan/redact call. Each analyze() has a fixed cost
    (~1 ms even for one character), so many tiny strings must be bounded, not just long ones."""

    def __init__(self, max_strings: int, max_chars: int) -> None:
        self.max_strings, self.max_chars = max_strings, max_chars
        self.strings = self.chars = 0

    def charge(self, n: int) -> None:
        self.strings += 1
        self.chars += n
        if self.strings > self.max_strings or self.chars > self.max_chars:
            raise RedactionError("NER budget exceeded for this payload")


_GLUE = frozenset("[]{}<>()|/\\")
_BUDGET: ContextVar[_Budget | None] = ContextVar("datasec_ner_budget", default=None)


def _unclaimed_runs(claimed: bytearray, text: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    """Parts of [start, end) not already redacted, trimmed of edge punctuation/whitespace."""
    i = start
    while i < end:
        while i < end and claimed[i]:
            i += 1
        j = i
        while j < end and not claimed[j]:
            j += 1
        s, e = i, j
        while s < e and not text[s].isalnum():
            s += 1
        while e > s and not text[e - 1].isalnum():
            e -= 1
        if s < e:
            yield s, e
        i = j


def _load_analyzer(model: str) -> Any:
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise DataSecError("PresidioRedactor needs the optional extra: " + INSTALL_HINT.format(model=model)) from exc
    # Presidio would download a missing model at runtime; fail at startup instead.
    if not spacy.util.is_package(model):
        raise DataSecError(f"spaCy model {model!r} is not installed: python -m spacy download {model}")
    provider = NlpEngineProvider(
        nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}
    )
    return AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])


class PresidioRedactor(Redactor):
    """Regex first, then Presidio NER on the regex-redacted text. The pipeline asks for
    NER only on egress sinks; with ner=False this is exactly the regex Redactor."""

    ner_capable = True

    def __init__(
        self,
        detectors: Iterable[Detector] = DEFAULT_DETECTORS,
        *,
        entities: Iterable[str] = ("PERSON", "LOCATION"),
        model: str = "en_core_web_lg",
        score_threshold: float = 0.5,
        ner_max_chars: int = 20_000,
        ner_max_strings: int = 256,
        ner_max_total_chars: int = 50_000,
        scan_integers: bool = False,
        integer_fields: Iterable[str] | None = None,
    ) -> None:
        if isinstance(entities, str):
            raise TypeError("entities must be a collection of strings, not a bare str")
        super().__init__(detectors, scan_integers=scan_integers, integer_fields=integer_fields)
        self.entities = list(entities)
        self.score_threshold = score_threshold
        self.ner_max_chars = ner_max_chars
        self.ner_max_strings = ner_max_strings
        self.ner_max_total_chars = ner_max_total_chars
        self._analyzer = _load_analyzer(model)  # once; model load is the expensive part

    def scan(self, payload: Any, *, scan_integers: bool | None = None, ner: bool = True) -> dict[str, int]:
        found: Counter[str] = Counter()
        self._budgeted(payload, found, strict_keys=False, scan_integers=scan_integers, ner=ner)
        return dict(found)

    def redact(self, payload: Any, *, scan_integers: bool | None = None, ner: bool = True) -> RedactionResult:
        found: Counter[str] = Counter()
        out = self._budgeted(payload, found, strict_keys=True, scan_integers=scan_integers, ner=ner)
        return RedactionResult(out, dict(found))

    def _budgeted(
        self, payload: Any, found: Counter[str], *, strict_keys: bool, scan_integers: bool | None, ner: bool,
    ) -> Any:
        token = _BUDGET.set(_Budget(self.ner_max_strings, self.ner_max_total_chars))
        try:
            return self._walk(payload, found, strict_keys=strict_keys, ints=self._ints(scan_integers), ner=ner)
        finally:
            _BUDGET.reset(token)

    def _redact_text(self, text: str, found: Counter[str], *, ner: bool = False) -> str:
        text, placeholders = self._redact_spans(text, found)
        if not ner or not text.strip():
            return link_locations(text, found)
        if len(text) > self.ner_max_chars:
            raise RedactionError("text too long for NER")
        budget = _BUDGET.get()
        if budget is not None:
            budget.charge(len(text))
        # Only brackets the regex pass actually wrote are ours; mask them with spaces
        # (same length, offsets unchanged) so they don't confuse spaCy's tokenizer.
        claimed = bytearray(len(text))
        masked = list(text)
        for s, e in placeholders:
            claimed[s:e] = b"\x01" * (e - s)
            masked[s:e] = " " * (e - s)
        # Bracket-like punctuation glued to a name ("[NOTE]Angela") hides it from spaCy's
        # tokenizer; give the model spaces there too. Same length, so offsets still hold.
        for i, ch in enumerate(masked):
            if ch in _GLUE:
                masked[i] = " "
        results = self._analyzer.analyze(
            text="".join(masked), entities=self.entities, language="en", score_threshold=self.score_threshold
        )
        spans: list[tuple[int, int, str]] = []
        for r in sorted(results, key=lambda r: (-r.score, -(r.end - r.start))):
            # Clip, never drop: an entity overlapping a placeholder still has its name part redacted.
            runs = list(_unclaimed_runs(claimed, text, r.start, r.end))
            for s, e in runs:
                claimed[s:e] = b"\x01" * (e - s)
                spans.append((s, e, r.entity_type))
            if runs:
                found[r.entity_type] += 1
        if not spans:
            return link_locations(text, found)
        spans.sort()
        parts: list[str] = []
        pos = 0
        for start, end, label in spans:
            parts.append(text[pos:start])
            parts.append(f"[{label}]")
            pos = end
        parts.append(text[pos:])
        return link_locations("".join(parts), found)
