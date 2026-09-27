import time

import pytest

from datasec.errors import RedactionError, UnsupportedPayload
from datasec.redaction import RedactionResult, Redactor, luhn_valid

R = Redactor()


@pytest.mark.parametrize(
    "text,label",
    [
        ("jane.doe@example.com", "EMAIL"),
        ("a+tag@mail.example.co.uk", "EMAIL"),
        ("123-45-6789", "SSN"),
        ("123 45 6789", "SSN"),
        ("123456789", "SSN"),
        ("4111 1111 1111 1111", "CREDIT_CARD"),
        ("4111-1111-1111-1111", "CREDIT_CARD"),
        ("4111111111111111", "CREDIT_CARD"),
        ("(555) 123-4567", "PHONE"),
        ("+1 555 123 4567", "PHONE"),
        ("555.123.4567", "PHONE"),
        ("10.0.0.1", "IPV4"),
        ("192.168.1.254", "IPV4"),
    ],
)
def test_each_detector_finds_and_redacts(text, label):
    sentence = f"contact: {text} thanks"
    assert R.scan(sentence) == {label: 1}
    assert R.redact(sentence) == RedactionResult(f"contact: [{label}] thanks", {label: 1})


def test_luhn():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("1234")


def test_luhn_invalid_number_is_not_flagged():
    assert R.scan("order 4111111111111112 shipped") == {}


def test_invalid_ip_is_not_flagged():
    assert R.scan("host 999.1.1.1") == {}


def test_multiple_findings_in_one_string():
    res = R.redact("a@x.com, b@y.org, ssn 123-45-6789")
    assert res.payload == "[EMAIL], [EMAIL], ssn [SSN]"
    assert res.found == {"EMAIL": 2, "SSN": 1}


def test_clean_text_scans_empty_and_is_unchanged():
    text = "nothing to see here ✨"
    assert R.scan(text) == {}
    assert R.redact(text).payload == text


def test_nested_payload_keeps_shape_and_scalars():
    payload = {
        "to": "jane@example.com",
        "items": ["ssn 123-45-6789", 5, None, True, 1.5],
        "meta": ("ok",),
    }
    res = R.redact(payload)
    assert res.payload == {
        "to": "[EMAIL]",
        "items": ["ssn [SSN]", 5, None, True, 1.5],
        "meta": ("ok",),
    }
    assert res.found == {"EMAIL": 1, "SSN": 1}
    assert payload["to"] == "jane@example.com"


def test_pii_in_dict_keys_is_found_and_redacted():
    assert R.scan({"jane@example.com": 1}) == {"EMAIL": 1}
    assert R.redact({"jane@example.com": 1}).payload == {"[EMAIL]": 1}


def test_non_string_scalar_keys_pass_through():
    assert R.redact({1: "x", None: "y"}).payload == {1: "x", None: "y"}


def test_redacted_key_collision_raises_but_scan_does_not():
    payload = {"a@x.com": 1, "b@x.com": 2}
    assert R.scan(payload) == {"EMAIL": 2}
    with pytest.raises(RedactionError):
        R.redact(payload)


@pytest.mark.parametrize(
    "payload",
    [b"jane@example.com", {"k": object()}, [bytearray(b"x")], {("tuple", "key"): 1}],
)
def test_unsupported_types_raise(payload):
    with pytest.raises(UnsupportedPayload):
        R.scan(payload)
    with pytest.raises(UnsupportedPayload):
        R.redact(payload)


def test_zero_width_characters_do_not_hide_pii():
    assert R.scan("jane​@exam‍ple.com") == {"EMAIL": 1}


def test_fullwidth_digits_are_normalized():
    assert R.redact("ssn １２３-４５-６７８９").payload == "ssn [SSN]"


def test_many_matches_stay_fast():
    text = " ".join(f"user{i}@example.com" for i in range(50_000))
    start = time.perf_counter()
    assert R.scan(text) == {"EMAIL": 50_000}
    assert time.perf_counter() - start < 1.0
