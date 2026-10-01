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


@pytest.mark.parametrize(
    "text,names",
    [
        ("name,email,phone\nAngela Merkel,angela@example.com,555-123-4567\n"
         "Barack Obama,barack@example.com,555-987-6543\n", ["Angela Merkel", "Barack Obama"]),
        ("Jane Doe<jane@x.com>", ["Jane Doe"]),
        ("Barack Obama,123-45-6789", ["Barack", "Obama"]),
        ("Angela Merkel[X]", ["Angela Merkel"]),
        ("Ship to [NOTE]Angela Merkel", ["Angela Merkel"]),
    ],
    ids=["csv_rows", "name_angle_email", "name_comma_ssn", "user_bracket_after", "user_bracket_before"],
)
def test_names_next_to_placeholders_are_redacted(ner, text, names):
    out = ner.redact(text).payload
    for name in names:
        assert name not in out


def test_ipv4_placeholder_preserved(ner):
    r = ner.redact("Angela Merkel/10.0.0.1")
    assert "[IPV4]" in r.payload
    assert "Angela Merkel" not in r.payload
    assert r.found.get("IPV4") == 1


def test_many_short_strings_hit_ner_budget(ner):
    import time

    p = SecurityPipeline(redactor=ner)
    start = time.perf_counter()
    r = p.guard(Action("llm", "chat", USER), ["a"] * 200_000)
    assert time.perf_counter() - start < 2.0
    assert not r.allowed
    assert r.decision.reason == "scan failed"


def test_total_ner_chars_budget(ner):
    r = SecurityPipeline(redactor=ner).guard(Action("llm", "chat", USER), ["word " * 3000] * 10)
    assert not r.allowed
    assert r.decision.reason == "scan failed"
