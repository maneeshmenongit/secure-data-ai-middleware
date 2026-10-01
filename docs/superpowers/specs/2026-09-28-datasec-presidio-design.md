# DataSec — Presidio NER Redactor Design

**Date:** 2026-09-28 · **Status:** awaiting review · **Parents:** Phase 2 spec §8 (deferred), DESIGN.md §10.8

## 1. Purpose and scope

Catch the free-text PII that regex cannot: **people's names (PERSON) and places/addresses (LOCATION)**. The detection is added as an optional NER pass behind the existing `Redactor` interface.

Not in scope:
- Presidio's email, SSN and card recognizers. They are regex-based, so R2g.1 and R2g.2 (PII spelled out in words) stay known gaps.
- Other entity types.
- Non-English models.

## 2. Constraints

- The base install stays dependency-free. There is a new optional extra, `datasec[presidio]` = `presidio-analyzer>=2.2` and `spacy>=3.7`. The model `en_core_web_lg` (~400 MB) is installed separately with `python -m spacy download en_core_web_lg`, as documented in the README.
- The regex `Redactor` stays the default and the fast path. Every Phase 1 and Phase 2 contract still holds.
- Fail closed. An NER error, or text over the size limit, ends in DENY with an audit entry.
- The model loads once, at construction, never per request.

## 3. Design

### 3.1 `src/datasec/presidio.py`

`PresidioRedactor(Redactor)` has this constructor:

```python
PresidioRedactor(
    detectors=DEFAULT_DETECTORS, *,
    entities=("PERSON", "LOCATION"),
    model="en_core_web_lg",
    score_threshold=0.5,
    ner_max_chars=20_000,
    scan_integers=False, integer_fields=None,
)
```

- **Construction** builds a Presidio `AnalyzerEngine` on a spaCy NLP engine for `model`. If `presidio_analyzer`, `spacy` or the model is missing, it raises `DataSecError` with the install hint. `entities` given as a bare `str` raises `TypeError`, consistent with the Phase 2 minors.
- **Capability flag:** the class attribute `ner_capable = True`.
- **Methods:** `scan(payload, *, scan_integers=None, ner=True)` and `redact(payload, *, scan_integers=None, ner=True)`. They reuse the regex walker, so nested payloads, dict keys, key collisions and integer scoping behave identically.
- **For each string, when `ner=True`:**
  1. Run the regex redaction first.
  2. If the resulting string is longer than `ner_max_chars`, raise `RedactionError("text too long for NER")`.
  3. Run `analyzer.analyze(text, entities=..., language="en", score_threshold=...)` on the regex-redacted text, so placeholders are never re-analysed.
  4. Resolve overlapping results by keeping the highest score, then the longest span.
  5. Replace each span with `[PERSON]` or `[LOCATION]` and count it in the tally.
- **When `ner=False`,** the behaviour is exactly the regex `Redactor`.
- **Thread-safety:** the per-call `ner` flag is passed explicitly down the walk. There is no instance state per call.

### 3.2 Pipeline integration (`pipeline.py`)

- When `getattr(self.redactor, "ner_capable", False)` is true, `scan` and `redact` receive `ner=(action.sink in EGRESS)`. Other redactors get exactly the Phase 2 calls, so custom redactors are unaffected.
- `_safe()` (audit metadata: `source`, `name`, `destination`) calls `redact(str(value), ner=True)` on NER-capable redactors, so names in metadata are redacted too. On failure it already falls back to `[UNREDACTABLE]`.
- Errors take the existing paths: `scan failed` / `redaction failed` → DENY, with an audit entry.

Why egress only is lossless: `pii` labels only change the outcome on egress sinks (`redact_pii_on_egress`). Non-egress sinks skip the model cost and give up nothing but tally detail in the audit entry.

### 3.3 Red-team support

- `Attack` gains `requires: str | None = None`, the name of an importable module. When the runner sees a missing requirement, it records `status: "skipped"` and does not count the attack as unexpected. The scorecard gains a `skipped` count.
- In pytest, such attacks are skipped with the reason.
- `PresidioRedactor` construction also needs the model. Attacks with `requires="presidio_analyzer"` treat a `DataSecError` at construction as `skipped` too.

## 4. Testing

`tests/test_presidio.py` uses the marker `presidio` and is skipped at module level unless `presidio_analyzer`, `spacy` and the model are importable. It covers:

- `"Please email Jane Doe in Seattle"` → `"Please email [PERSON] in [LOCATION]"` (or `[PERSON]` alone if the model does not tag Seattle; the assertion requires `[PERSON]` and no raw `Jane Doe`).
- Nested payloads and dict keys containing names are redacted.
- Regex placeholders are untouched: `"[EMAIL]"` never becomes `[PERSON]`.
- Parity: every string case in `tests/test_redaction.py::test_each_detector_finds_and_redacts`, and every R2 payload that the regex path redacts, redacts under `PresidioRedactor` with no raw PII remaining.
- The pipeline calls NER only on egress sinks. A counting wrapper around the analyzer shows zero calls for `tool:readonly` and `memory:write`, and at least one for `llm`.
- A name in `Action.provenance.source` is redacted in the audit entry.
- A string over `ner_max_chars` to `llm` gives DENY (`redaction failed` or `scan failed`), with an audit entry.
- These run without the optional libraries, as base tests: a missing library or model makes construction raise `DataSecError` with the install hint (a monkeypatched import); `entities` given as a bare `str` raises `TypeError`.

Red team:

| ID | Payload | Setup | Expect |
|---|---|---|---|
| R2.17 | "Ship it to Jane Doe, 1600 Pennsylvania Ave, Washington" → llm | `PresidioRedactor` | redacted (skipped without Presidio) |
| R2g.4 | the same payload | default regex redactor | known_gap |
| R6.9 | a 25k-char string → llm | `PresidioRedactor` | blocked, in under 1 s (skipped without Presidio) |

## 5. Done

- `uv run pytest` passes both with and without the `presidio` extra installed. With it, the Presidio tests run.
- `python -m redteam.runner` reports 0 unexpected. Presidio attacks count as `skipped` when the extra is absent.
- README documents the extra, the model download, and the 20k-character limit trade-off.
- DESIGN.md §10.8 is marked implemented.
