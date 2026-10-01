"""Optional NER pass for people and places, behind the Redactor interface.

Install: pip install 'datasec[presidio]' && python -m spacy download en_core_web_lg
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

from .errors import DataSecError, RedactionError
from .redaction import DEFAULT_DETECTORS, Detector, RedactionResult, Redactor

INSTALL_HINT = "pip install 'datasec[presidio]' && python -m spacy download {model}"
_PLACEHOLDER = re.compile(r"\[[A-Z_]+\]")


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
        scan_integers: bool = False,
        integer_fields: Iterable[str] | None = None,
    ) -> None:
        if isinstance(entities, str):
            raise TypeError("entities must be a collection of strings, not a bare str")
        super().__init__(detectors, scan_integers=scan_integers, integer_fields=integer_fields)
        self.entities = list(entities)
        self.score_threshold = score_threshold
        self.ner_max_chars = ner_max_chars
        self._analyzer = _load_analyzer(model)  # once; model load is the expensive part

    def scan(self, payload: Any, *, scan_integers: bool | None = None, ner: bool = True) -> dict[str, int]:
        found: Counter[str] = Counter()
        self._walk(payload, found, strict_keys=False, ints=self._ints(scan_integers), ner=ner)
        return dict(found)

    def redact(self, payload: Any, *, scan_integers: bool | None = None, ner: bool = True) -> RedactionResult:
        found: Counter[str] = Counter()
        out = self._walk(payload, found, strict_keys=True, ints=self._ints(scan_integers), ner=ner)
        return RedactionResult(out, dict(found))

    def _redact_text(self, text: str, found: Counter[str], *, ner: bool = False) -> str:
        text = super()._redact_text(text, found)
        if not ner or not text.strip():
            return text
        if len(text) > self.ner_max_chars:
            raise RedactionError("text too long for NER")
        results = self._analyzer.analyze(
            text=text, entities=self.entities, language="en", score_threshold=self.score_threshold
        )
        claimed = bytearray(len(text))
        for m in _PLACEHOLDER.finditer(text):  # regex output is never re-tagged
            claimed[m.start():m.end()] = b"\x01" * (m.end() - m.start())
        spans: list[tuple[int, int, str]] = []
        for r in sorted(results, key=lambda r: (-r.score, -(r.end - r.start))):
            if any(claimed[r.start:r.end]):
                continue
            claimed[r.start:r.end] = b"\x01" * (r.end - r.start)
            spans.append((r.start, r.end, r.entity_type))
            found[r.entity_type] += 1
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
