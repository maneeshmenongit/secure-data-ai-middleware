from dataclasses import FrozenInstanceError

import pytest

from datasec.provenance import (
    Provenance,
    TrustLevel,
    combine,
    from_user,
    internal,
    untrusted,
)


def test_trust_levels_are_ordered_so_min_picks_weakest():
    assert (
        TrustLevel.UNTRUSTED
        < TrustLevel.EXTERNAL
        < TrustLevel.USER
        < TrustLevel.INTERNAL
        < TrustLevel.TRUSTED
    )
    assert min(TrustLevel.TRUSTED, TrustLevel.USER) is TrustLevel.USER


def test_provenance_is_immutable():
    p = Provenance(TrustLevel.USER, "user:1")
    with pytest.raises(FrozenInstanceError):
        p.trust = TrustLevel.TRUSTED


def test_with_labels_returns_new_provenance():
    p = Provenance(TrustLevel.USER, "user:1")
    q = p.with_labels("pii", "x")
    assert not p.has("pii")
    assert q.has("pii") and q.has("x")
    assert q.trust is TrustLevel.USER and q.source == "user:1"


def test_labels_given_as_string_are_one_label_not_characters():
    assert Provenance(TrustLevel.USER, "u", "pii").labels == frozenset({"pii"})
    assert untrusted("v", source="web", labels="pii").provenance.labels == frozenset({"pii"})


def test_trust_and_labels_are_coerced():
    p = Provenance(2, "u", {"a"})
    assert p.trust is TrustLevel.USER
    assert isinstance(p.labels, frozenset)


def test_map_keeps_provenance():
    t = untrusted(" hi ", source="web:x")
    m = t.map(str.strip)
    assert m.value == "hi"
    assert m.provenance == t.provenance


def test_combine_takes_weakest_trust_and_all_labels():
    a = internal("cfg", source="svc", labels=("secret",))
    b = untrusted("web", source="web:x", labels=("pii",))
    c = combine(a, b, source="prompt", value="cfg+web")
    assert c.value == "cfg+web"
    assert c.provenance.trust is TrustLevel.UNTRUSTED
    assert c.provenance.labels == frozenset({"secret", "pii"})
    assert c.provenance.source == "prompt"


def test_combine_defaults():
    c = combine(from_user("x", source="u"))
    assert c.provenance.source == "derived"
    assert c.value is None


def test_combine_requires_at_least_one_input():
    with pytest.raises(ValueError):
        combine()


def test_boundary_constructors_set_trust():
    assert untrusted(1, source="s").provenance.trust is TrustLevel.UNTRUSTED
    assert from_user(1, source="s").provenance.trust is TrustLevel.USER
    assert internal(1, source="s").provenance.trust is TrustLevel.INTERNAL


def test_labels_are_case_and_whitespace_insensitive():
    p = Provenance(TrustLevel.USER, "u", {"PII", " Secret "})
    assert p.labels == frozenset({"pii", "secret"})
    assert p.has("Pii") and p.has(" SECRET")


def test_with_labels_normalizes():
    p = Provenance(TrustLevel.USER, "u").with_labels("SECRET")
    assert p.labels == frozenset({"secret"})


def test_non_string_label_rejected():
    with pytest.raises(TypeError):
        Provenance(TrustLevel.USER, "u", [1, "a"])


def test_empty_label_rejected():
    with pytest.raises(ValueError):
        Provenance(TrustLevel.USER, "u", {"  "})
