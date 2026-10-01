# DataSec Presidio NER Redactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional `PresidioRedactor` that redacts people's names (PERSON) and places (LOCATION) on egress sinks, behind the existing `Redactor` interface.

**Architecture:**
- The regex walker gains a `ner` flag that it threads down to every string. The base `Redactor` ignores it.
- `PresidioRedactor` subclasses `Redactor`. It runs regex first, then a Presidio/spaCy pass over the regex-redacted text.
- The pipeline passes `ner=(sink in EGRESS)` only to redactors that set `ner_capable = True`, so the model never runs for tool or memory calls.
- The red team learns to skip attacks whose optional dependency is absent.

**Tech Stack:**
- Python ≥3.11, stdlib core.
- Optional extra `datasec[presidio]`: `presidio-analyzer` (2.2.364 resolves on 3.13) and `spacy` (3.8.16).
- The model `en_core_web_lg` 3.8.0 comes from a dedicated uv dependency group.

**Spec:** [docs/superpowers/specs/2026-09-28-datasec-presidio-design.md](../specs/2026-09-28-datasec-presidio-design.md)

## Global Constraints

- The base install stays dependency-free. Presidio and spaCy go only in `[project.optional-dependencies] presidio`. The model goes only in the `presidio-model` dependency group.
- Every existing test and red-team attack keeps passing unchanged.
- Fail closed. An NER error, or a string over `ner_max_chars` (20_000), on an egress sink becomes DENY with an audit entry.
- Load the model once, at construction. Presidio auto-downloads missing spaCy models, so check `spacy.util.is_package(model)` first and raise `DataSecError` instead of downloading at runtime.
- Tests that need the model skip cleanly when it is absent.
- The red-team runner must end with `0 unexpected` both with and without the extra.
- Commits end with the trailer `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`, passed as a second `-m`.
- **Ruling carried by this plan:** spec §3.2 applies NER to all audit metadata, while §4 wants zero analyzer calls for non-egress sinks. The two conflict because metadata is recorded for every sink. Resolution:
  - NER runs on the caller-supplied free text `name`, `source` and `destination` only. `sink`, `reason`, `rule` and `labels` stay regex-only.
  - The §4 test asserts the **payload** text is never analyzed off-egress.
  - Cost if wrong: a name inside a custom rule's reason string is not NER-redacted in the audit.
- **Ruling carried by this plan:** install the model from a pinned wheel in a uv dependency group, not with `python -m spacy download`, because uv venvs have no `pip`. The README still documents `spacy download` for pip users.

## Review Focus

1. A redactor with the Phase 1 signature (`scan(self, payload)`) must not receive `ner=` → Task 1 `test_plain_redactor_gets_no_ner_kwarg`.
2. A regex placeholder such as `[EMAIL]` must never be re-tagged as a PERSON or LOCATION → Task 2 `test_regex_placeholders_untouched`.
3. A name used as a dict key must be redacted, and a key collision after NER must DENY, not overwrite → Task 2 `test_names_in_keys_and_nesting` and `test_ner_key_collision_denied`.
4. A missing spaCy model must fail at construction with a hint, never trigger a runtime download → Task 2 `test_missing_model_is_a_clear_error`.
5. An attack whose dependency is missing must be reported `skipped`, never `unexpected` or `error:` → Task 1 `test_missing_requirement_is_skipped`.

---

### Task 1: `ner` plumbing, pipeline routing, red-team `skipped`

**Files:**
- Modify: `src/datasec/redaction.py` (`_walk`, `_redact_text`)
- Modify: `src/datasec/pipeline.py`
- Modify: `redteam/common.py`, `redteam/runner.py`
- Test: `tests/test_pipeline.py`, `tests/test_redteam.py`

**Interfaces:**
- Produces:
  - `Redactor._walk(..., ner: bool = False)` and `Redactor._redact_text(text, found, *, ner: bool = False)`. The base class ignores `ner`.
  - The pipeline passes `ner=action.sink in EGRESS` to `scan` and `redact` when `getattr(redactor, "ner_capable", False)` is true.
  - `SecurityPipeline._safe(value, *, ner=False)`.
  - `Attack(..., requires: str | None = None)`.
  - Runner status `"skipped"`, and a scorecard key `"skipped"`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_pipeline.py`:
```python


class SpyNER(Redactor):
    """Stands in for an NER-capable redactor: records every call and its ner flag."""

    ner_capable = True

    def __init__(self):
        super().__init__()
        self.calls = []

    def scan(self, payload, *, scan_integers=None, ner=True):
        self.calls.append(("scan", payload, ner))
        return super().scan(payload, scan_integers=scan_integers)

    def redact(self, payload, *, scan_integers=None, ner=True):
        self.calls.append(("redact", payload, ner))
        return super().redact(payload, scan_integers=scan_integers)


@pytest.mark.parametrize(
    "sink,expected",
    [("llm", True), ("http:response", True), ("tool:readonly", False), ("memory:write", False)],
)
def test_ner_flag_follows_egress(sink, expected):
    spy = SpyNER()
    SecurityPipeline(redactor=spy).guard(Action(sink, "op", USER), "payload-text")
    assert [ner for kind, payload, ner in spy.calls if payload == "payload-text"] == [expected]


def test_metadata_ner_only_for_caller_text():
    spy = SpyNER()
    prov = from_user("", source="user:Jane Doe").provenance
    SecurityPipeline(redactor=spy).guard(
        Action("tool:readonly", "lookup Jane", prov, destination="api.example"), "x"
    )
    ner_texts = {payload for kind, payload, ner in spy.calls if kind == "redact" and ner}
    assert ner_texts == {"lookup Jane", "user:Jane Doe", "api.example"}


def test_plain_redactor_gets_no_ner_kwarg():
    class Legacy(Redactor):
        def scan(self, payload):
            return super().scan(payload)

        def redact(self, payload):
            return super().redact(payload)

    r = SecurityPipeline(redactor=Legacy()).guard(Action("llm", "chat", USER), "mail jane@example.com")
    assert r.payload == "mail [EMAIL]"
```

In `tests/test_redteam.py`, add `import importlib.util` to the imports and replace `test_attack` with:
```python
@pytest.mark.parametrize("attack", [_param(a) for a in ATTACKS])
def test_attack(attack):
    if attack.requires and importlib.util.find_spec(attack.requires) is None:
        pytest.skip(f"needs optional {attack.requires}")
    observed = attack.run()
    if observed == "skipped":
        pytest.skip("optional dependency unavailable")
    if attack.expect == "known_gap":
        assert observed in DEFENDED  # xfail(strict): passes only once the gap is fixed
    else:
        assert observed == attack.expect
```
and append:
```python


def test_missing_requirement_is_skipped():
    a = Attack("F9", "c", "o", "d", lambda: "blocked", "blocked", requires="no_such_module_xyz")
    card = run_all([a])
    assert card["results"][0]["status"] == "skipped"
    assert (card["skipped"], card["unexpected"]) == (1, 0)


def test_attack_reporting_skipped_is_skipped():
    card = run_all([Attack("F10", "c", "o", "d", lambda: "skipped", "redacted")])
    assert card["results"][0]["status"] == "skipped"
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `uv run pytest tests/test_pipeline.py tests/test_redteam.py -q 2>&1 | grep -E "^FAILED|^ERROR|passed|failed" | sed 's/ - .*//'`
Expected: FAIL.
- `test_ner_flag_follows_egress[*]` fails because the spy records `ner=True` (its default) for every sink.
- `test_metadata_ner_only_for_caller_text` fails with an empty set.
- The redteam tests fail with a `TypeError` for an unexpected keyword `requires`, and the skipped-status assertion fails.
- `test_plain_redactor_gets_no_ner_kwarg` passes already. It's a guard against regressions.

- [ ] **Step 3: Implement**

In `src/datasec/redaction.py`, replace the whole `_walk` method with:
```python
    def _walk(
        self, payload: Any, found: Counter[str], *, strict_keys: bool, ints: bool,
        field: str | None = None, ner: bool = False,
    ) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload, found, ner=ner)
        if isinstance(payload, _SCALARS):
            return self._redact_int(payload, found) if self._int_in_scope(ints, field) else payload
        if isinstance(payload, dict):
            out: dict[Any, Any] = {}
            for key, value in payload.items():
                if isinstance(key, str):
                    new_key = self._redact_text(key, found, ner=ner)
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
```
and change the `_redact_text` signature line to:
```python
    def _redact_text(self, text: str, found: Counter[str], *, ner: bool = False) -> str:
```
The body is unchanged, because the base regex redactor ignores `ner`. `_redact_int` keeps calling `self._redact_text(text, found)`, since NER on a digit string is pointless.

In `src/datasec/pipeline.py`, change the policy import to:
```python
from .policy import EGRESS, KNOWN_SINKS, Action, Decision, Effect, PolicyEngine, default_rules
```
replace:
```python
        ints = {"scan_integers": True} if action.scan_integers else {}
```
with:
```python
        ints: dict[str, bool] = {"scan_integers": True} if action.scan_integers else {}
        if getattr(self.redactor, "ner_capable", False):
            ints["ner"] = action.sink in EGRESS  # the model only runs where pii changes the outcome
```
In `guard`, change `self._safe(action.destination)` to `self._safe(action.destination, ner=True)`. In `_record`, change `name=self._safe(action.name),` to `name=self._safe(action.name, ner=True),` and `source=self._safe(prov.source) if prov else "",` to `source=self._safe(prov.source, ner=True) if prov else "",`. Replace `_safe` with:
```python
    def _safe(self, value: Any, *, ner: bool = False) -> str:
        """Caller-supplied metadata (names, labels, custom rule text) can carry PII; redact it.
        NER runs only on caller free text (name, source, destination), never per rule string."""
        # Explicit ner=False matters: an NER-capable redactor defaults to ner=True.
        kwargs = {"ner": ner} if getattr(self.redactor, "ner_capable", False) else {}
        try:
            return self.redactor.redact(str(value), **kwargs).payload
        except Exception:
            return "[UNREDACTABLE]"
```

In `redteam/common.py`, add this field to the end of `Attack`, after `expect`:
```python
    requires: str | None = None  # importable module an optional attack depends on
```

In `redteam/runner.py`, add `import importlib.util` to the imports, and change `STATUSES` to:
```python
STATUSES = ("pass", "known_gap", "fixed_gap", "unexpected", "skipped")
```
In `Result.status`, insert this as the first statement of the method:
```python
        if self.observed == "skipped":
            return "skipped"
```
Replace `run_attack` with:
```python
def run_attack(attack: Attack) -> Result:
    if attack.requires and importlib.util.find_spec(attack.requires) is None:
        observed = "skipped"
    else:
        try:
            observed = attack.run()
        except Exception as exc:
            observed = f"error:{type(exc).__name__}"
    return Result(attack.id, attack.category, attack.owasp, attack.description, attack.expect, observed)
```
In `run_all`'s returned dict, add after the `"known_gaps"` line:
```python
        "skipped": count("skipped"),
```
and in `main`, change the summary print to:
```python
    print(
        f"\n{card['passed']} passed, {card['known_gaps']} known gaps, {card['skipped']} skipped, "
        f"{card['unexpected']} unexpected / {card['total']} attacks"
    )
```

- [ ] **Step 4: Run the full suite and the runner**

Run: `uv run pytest -q 2>&1 | tail -1 && uv run python -m redteam.runner | tail -1`
Expected: `0 failed`, `7 xfailed`, and `63 passed, 7 known gaps, 0 skipped, 0 unexpected / 70 attacks`.

- [ ] **Step 5: Commit**

```bash
git add src/datasec/redaction.py src/datasec/pipeline.py redteam/common.py redteam/runner.py tests/test_pipeline.py tests/test_redteam.py
git commit -m "feat: route an ner flag to NER-capable redactors on egress; red-team skipped status" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `PresidioRedactor`

**Files:**
- Modify: `pyproject.toml`
- Create: `src/datasec/presidio.py`
- Test: `tests/test_presidio_base.py` (runs without the extra), `tests/test_presidio.py` (needs the extra and the model)

**Interfaces:**
- Consumes: the `_walk(..., ner=)` and `_redact_text(..., ner=)` hooks and the pipeline routing from Task 1.
- Produces: `datasec.presidio.PresidioRedactor(detectors=DEFAULT_DETECTORS, *, entities=("PERSON", "LOCATION"), model="en_core_web_lg", score_threshold=0.5, ner_max_chars=20_000, scan_integers=False, integer_fields=None)`, with:
  - `ner_capable = True`
  - `scan(payload, *, scan_integers=None, ner=True)` and `redact(payload, *, scan_integers=None, ner=True)`
  - the private `_analyzer` attribute, which the tests wrap to count calls

- [ ] **Step 1: Add the optional dependency and install it**

In `pyproject.toml`, add this to `[project.optional-dependencies]`:
```toml
presidio = ["presidio-analyzer>=2.2", "spacy>=3.7"]
```
add this to `[dependency-groups]`:
```toml
presidio-model = [
    "en-core-web-lg @ https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl",
]
```
and add this to `[tool.pytest.ini_options]`:
```toml
markers = ["presidio: needs the optional presidio extra and the en_core_web_lg model"]
```
Run: `uv sync --extra presidio --group presidio-model 2>&1 | tail -3`
Expected: `presidio-analyzer`, `spacy` and `en-core-web-lg` are installed. This is a ~400 MB download.

**Note for the implementer:** after this, run commands with `uv run --extra presidio --group presidio-model ...`, or keep using plain `uv run`. Plain `uv run` does not remove extras. Do **not** run a bare `uv sync`, which would uninstall them.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_presidio_base.py`:
```python
import sys

import pytest

from datasec.errors import DataSecError
from datasec.presidio import PresidioRedactor


def test_missing_libraries_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
    with pytest.raises(DataSecError, match="datasec\\[presidio\\]"):
        PresidioRedactor()


def test_missing_model_is_a_clear_error():
    with pytest.raises(DataSecError, match="spacy download"):
        PresidioRedactor(model="xx_no_such_model_sm")


def test_entities_as_bare_string_rejected():
    with pytest.raises(TypeError):
        PresidioRedactor(entities="PERSON")
```

Create `tests/test_presidio.py`:
```python
import json

import pytest

spacy = pytest.importorskip("spacy")
pytest.importorskip("presidio_analyzer")
if not spacy.util.is_package("en_core_web_lg"):
    pytest.skip("en_core_web_lg not installed", allow_module_level=True)

from datasec.pipeline import SecurityPipeline  # noqa: E402
from datasec.policy import Action  # noqa: E402
from datasec.presidio import PresidioRedactor  # noqa: E402
from datasec.provenance import from_user  # noqa: E402
from datasec.redaction import Redactor  # noqa: E402

pytestmark = pytest.mark.presidio
USER = from_user("", source="user:req-1").provenance


@pytest.fixture(scope="module")
def ner():
    return PresidioRedactor()


class Counting:
    def __init__(self, inner):
        self.inner = inner
        self.texts = []

    def analyze(self, text, **kwargs):
        self.texts.append(text)
        return self.inner.analyze(text=text, **kwargs)


def test_person_redacted(ner):
    out = ner.redact("Please email Jane Doe in Seattle").payload
    assert "[PERSON]" in out
    assert "Jane Doe" not in out


def test_names_in_keys_and_nesting(ner):
    out = ner.redact({"note": ["call Barack Obama tomorrow"], "Angela Merkel": 1}).payload
    text = json.dumps(out)
    assert "Barack Obama" not in text and "Angela Merkel" not in text


def test_ner_key_collision_denied(ner):
    p = SecurityPipeline(redactor=ner)
    r = p.guard(Action("llm", "chat", USER), {"Barack Obama": 1, "Angela Merkel": 2})
    assert not r.allowed
    assert r.decision.reason == "redaction failed"


def test_regex_placeholders_untouched(ner):
    assert ner.redact("mail jane@example.com").payload == "mail [EMAIL]"


def test_ner_off_is_regex_only(ner):
    assert ner.redact("Please email Jane Doe", ner=False).payload == "Please email Jane Doe"


PARITY = [
    "contact: jane.doe@example.com thanks",
    "ssn 123-45-6789",
    "card 4111 1111 1111 1111 123",
    "call (555) 123-4567",
    "host 10.0.0.1",
    "ssn １２３-４５-６７８９",
    "mail jane​@exam‌ple.com",
    "ssn 123.45.6789",
]


@pytest.mark.parametrize("text", PARITY)
def test_parity_with_regex(ner, text):
    base = Redactor().redact(text)
    full = ner.redact(text)
    for label, n in base.found.items():
        assert full.found.get(label, 0) >= n
        assert full.payload.count(f"[{label}]") >= n


def test_payload_never_analyzed_off_egress(ner, monkeypatch):
    spy = Counting(ner._analyzer)
    monkeypatch.setattr(ner, "_analyzer", spy)
    p = SecurityPipeline(redactor=ner)
    for sink in ("tool:readonly", "memory:write"):
        p.guard(Action(sink, "op", USER), "Meet Jane Doe")
    assert "Meet Jane Doe" not in spy.texts
    r = p.guard(Action("llm", "chat", USER), "Meet Jane Doe")
    assert "Meet Jane Doe" in spy.texts
    assert "Jane Doe" not in r.payload


def test_name_in_action_name_redacted_in_audit(ner):
    p = SecurityPipeline(redactor=ner)
    p.guard(Action("llm", "email Jane Doe about the refund", USER), "hi")
    assert "Jane Doe" not in list(p.audit)[-1].name


def test_over_limit_text_denied(ner):
    p = SecurityPipeline(redactor=ner)
    r = p.guard(Action("llm", "chat", USER), "word " * 5000)
    assert not r.allowed
    assert r.decision.reason == "scan failed"
    assert list(p.audit)[-1].effect == "deny"
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `uv run pytest tests/test_presidio_base.py tests/test_presidio.py -q 2>&1 | grep -E "^E  |passed|failed|error" | head -5`
Expected: collection errors, `ModuleNotFoundError: No module named 'datasec.presidio'`.

- [ ] **Step 4: Implement `src/datasec/presidio.py`**

```python
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
```

- [ ] **Step 5: Run the full suite and the runner**

Run: `uv run pytest -q 2>&1 | tail -1 && uv run pytest tests/test_presidio.py -q 2>&1 | tail -1 && uv run python -m redteam.runner | tail -1`
Expected:
- The full suite shows `0 failed` and `7 xfailed`.
- The Presidio file runs, rather than being skipped, and passes: 16 tests, since the parity case is parametrized ×8.
- The runner is unchanged: `63 passed, 7 known gaps, 0 skipped, 0 unexpected / 70 attacks`.

If a model-dependent assertion fails because spaCy does not tag a particular name, do not weaken the redactor. Swap the name for a better-known one and record a `Ruling:` in the ledger.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock src/datasec/presidio.py tests/test_presidio_base.py tests/test_presidio.py
git commit -m "feat: optional PresidioRedactor for names and places on egress" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Red-team attacks + docs

**Files:**
- Modify: `redteam/common.py`, `redteam/attacks/evasion.py`, `redteam/attacks/resource.py`
- Modify: `README.md`, `DESIGN.md`

**Interfaces:**
- Consumes: `PresidioRedactor` and `Attack.requires`.
- Produces: `redteam.common.presidio_pipeline() -> SecurityPipeline | None`, which is cached and returns `None` when the extra or model is absent. Also the attacks R2.17, R2g.4 and R6.9.

- [ ] **Step 1: Write the attacks (red first)**

In `redteam/common.py`, add `import functools` and `from datasec.errors import DataSecError` to the imports, and add at the end:
```python
@functools.lru_cache(maxsize=1)
def presidio_pipeline() -> SecurityPipeline | None:
    """A pipeline with the NER redactor, loaded once; None when the optional extra/model is absent."""
    try:
        from datasec.presidio import PresidioRedactor

        return SecurityPipeline(redactor=PresidioRedactor())
    except DataSecError:
        return None
```

In `redteam/attacks/evasion.py`, change the common import to:
```python
from redteam.common import Attack, guard, presidio_pipeline
```
add above `ATTACKS`:
```python
NAME_AND_ADDRESS = "Ship it to Jane Doe, 1600 Pennsylvania Ave, Washington"


def _names_with_presidio():
    p = presidio_pipeline()
    if p is None:
        return "skipped"
    return _pii(NAME_AND_ADDRESS, "Jane Doe", pipeline=p)()
```
and insert before the `R2g.1` entry:
```python
    Attack("R2.17", "pii_evasion", "LLM02", "person's name and address sent to the LLM (Presidio configured)",
           _names_with_presidio, "redacted", requires="presidio_analyzer"),
```
and append after `R2g.3`:
```python
    Attack("R2g.4", "pii_evasion", "LLM02", "person's name and address under the default regex redactor",
           _pii(NAME_AND_ADDRESS, "Jane Doe"), "known_gap"),
```

In `redteam/attacks/resource.py`, change the common import to:
```python
from redteam.common import Attack, guard, outcome, presidio_pipeline
```
add above `ATTACKS`:
```python
def _over_ner_limit():
    p = presidio_pipeline()
    if p is None:
        return "skipped"
    start = time.perf_counter()
    result = outcome(guard("llm", from_user("", source="user:attacker").provenance, "word " * 5000, pipeline=p))
    return result if time.perf_counter() - start < LIMIT_SECONDS else "slow"
```
and append to `ATTACKS`:
```python
    Attack("R6.9", "resource_abuse", "LLM10", "25k-char text to stall the NER model (Presidio configured)",
           _over_ner_limit, "blocked", requires="presidio_analyzer"),
```

- [ ] **Step 2: Run the red team**

Run: `uv run pytest tests/test_redteam.py -q 2>&1 | tail -1 && uv run python -m redteam.runner | tail -1`
Expected, with the extra installed: `0 failed`, `8 xfailed`, and `65 passed, 8 known gaps, 0 skipped, 0 unexpected / 73 attacks`. R2.17 and R6.9 pass and R2g.4 is xfailed.

These attacks go green immediately, because the control shipped in Task 2. They are the regression pins for it.

- [ ] **Step 3: Confirm the skip path without the extra**

Run: `uv run --isolated python -m redteam.runner | tail -1` (a throwaway env with only the default install, without the presidio extra or model).
Expected: `63 passed, 8 known gaps, 2 skipped, 0 unexpected / 73 attacks`.

If `--isolated` cannot resolve offline, verify the skip path through `test_missing_requirement_is_skipped` (Task 1) instead, and record a ledger note.

- [ ] **Step 4: Update docs**

In `README.md`, add after the "Configuration (Phase 2)" section:
````markdown
## Names and places (optional)

```bash
pip install 'datasec[presidio]'
python -m spacy download en_core_web_lg      # ~400 MB, loaded once at startup
```

```python
from datasec.presidio import PresidioRedactor
pipeline = SecurityPipeline(redactor=PresidioRedactor())   # PERSON + LOCATION on egress sinks
```

NER runs only on egress sinks (`llm`, `third_party`, `http:response`) and on caller-supplied
audit metadata. Any single string over 20,000 characters is **denied** on egress rather than sent
unanalyzed. Raise `ner_max_chars` if you need to send longer documents.
````
and add to "Current known gaps":
```markdown
- People's names and places when Presidio is not configured (regex can't recognize them).
```
In `DESIGN.md` §10, replace the `10.8 Presidio — [deferred]` line with:
```markdown
- **10.8 Presidio — [implemented].** Optional `PresidioRedactor` (PERSON, LOCATION; `en_core_web_lg`) behind the `Redactor` interface, egress sinks only; strings over 20k chars are denied on egress. Its email/SSN recognizers are regex-based, so R2g.1/R2g.2 remain known gaps.
```

- [ ] **Step 5: Full verification and commit**

Run: `uv run pytest -q 2>&1 | tail -1 && uv run python demo.py | tail -1 && uv run python -m redteam.runner | tail -1`
Expected: `0 failed`, `8 xfailed`; `[audit] intact=True tamper_detected=True`; `65 passed, 8 known gaps, 0 skipped, 0 unexpected / 73 attacks`.

```bash
git add redteam README.md DESIGN.md
git commit -m "feat: Presidio red-team attacks (R2.17, R2g.4, R6.9); document the NER extra" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
