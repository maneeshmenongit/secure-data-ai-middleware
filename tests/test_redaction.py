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


@pytest.mark.parametrize(
    "text",
    [
        "card 4111 1111 1111 1111 123",
        "4111111111111111 123",
        "4111-1111-1111-1111-12",
        "Ref 7 4111 1111 1111 1111",
    ],
)
def test_card_adjacent_to_other_digits_is_redacted(text):
    res = R.redact(text)
    assert res.found.get("CREDIT_CARD") == 1
    assert "4111" not in res.payload


@pytest.mark.parametrize(
    "text,label",
    [
        ("123­45­6789", "SSN"),        # soft hyphen
        ("123‎45‎6789", "SSN"),        # left-to-right mark
        ("123⁦45-6789", "SSN"),             # bidi isolate
        ("1͏23-45-6789", "SSN"),            # combining grapheme joiner
        ("123️-45-6789", "SSN"),            # variation selector
        ("123–45–6789", "SSN"),        # en-dash separators
        ("4111–1111–1111–1111", "CREDIT_CARD"),
        ("555–123–4567", "PHONE"),
    ],
)
def test_invisible_and_dash_characters_do_not_hide_pii(text, label):
    res = R.redact(f"x {text} y")
    assert res.found == {label: 1}
    assert res.payload == f"x [{label}] y"


def test_soft_hyphen_in_email_does_not_leak_local_part():
    assert R.redact("john­.doe@example.com").payload == "[EMAIL]"


def test_integers_pass_through_by_default():
    payload = {"order_id": 123456789, "card": 4111111111111111, 123456789: "k"}
    assert R.scan(payload) == {}
    assert R.redact(payload).payload == payload


def test_integer_scanning_is_opt_in():
    r = Redactor(scan_integers=True)
    payload = {"card": 4111111111111111, "ssn": 123456789, "n": 42, 123456789: "k"}
    assert r.scan(payload) == {"CREDIT_CARD": 1, "SSN": 2}
    assert r.redact(payload).payload == {
        "card": "[CREDIT_CARD]", "ssn": "[SSN]", "n": 42, "[SSN]": "k",
    }


def test_per_call_flag_enables_integer_scanning():
    assert R.scan({"c": 4111111111111111}, scan_integers=True) == {"CREDIT_CARD": 1}


def test_integer_fields_limit_scope():
    r = Redactor(scan_integers=True, integer_fields={"SSN"})
    payload = {"ssn": 123456789, "order_id": 123456789, "nested": {"ssn": [123456789]}, 123456789: "k"}
    assert r.redact(payload).payload == {
        "ssn": "[SSN]", "order_id": 123456789, "nested": {"ssn": ["[SSN]"]}, 123456789: "k",
    }


def test_ssn_with_dots_detected():
    assert R.redact("x 123.45.6789 y").payload == "x [SSN] y"


def test_decimal_number_is_not_an_ssn():
    assert R.scan("value 123.456789") == {}  # dotted-SSN rule must not match decimals


def test_integer_fields_as_bare_string_rejected():
    with pytest.raises(TypeError):
        Redactor(scan_integers=True, integer_fields="ssn")


def test_integer_fields_require_scan_integers():
    with pytest.raises(ValueError):
        Redactor(integer_fields={"ssn"})


def test_integer_field_scope_covers_nested_values():
    r = Redactor(scan_integers=True, integer_fields={"ssn"})
    payload = {"ssn": {"value": 123456789}, "other": {"value": 123456789}}
    assert r.redact(payload).payload == {"ssn": {"value": "[SSN]"}, "other": {"value": 123456789}}


REPORTED = (
    "Hi there my name is Maneesh and I live in 145 washington St, New Brunswick,  NJ 07922 and my phone "
    "number is 8900192015. I could provide my lat 82.98635 and long  its  23.140745\n\n\nWould you be able "
    "to connect to my payment method and pay my electricity bill and the account number is 59207220. Thanks"
)


def test_reported_message_regex_only():
    out = R.redact(REPORTED).payload
    # Regex alone can't recognise the city name ("New Brunswick"); everything else must go.
    for raw in ["Maneesh", "145", "washington", "NJ", "07922", "82.98635", "23.140745", "59207220", "8900192015"]:
        assert raw not in out


@pytest.mark.parametrize("text,expected", [
    ("ship to 1600 Pennsylvania Ave today", "ship to [ADDRESS] today"),
    ("at 22 Baker Street now", "at [ADDRESS] now"),
    ("mail NJ 07922 ok", "mail [ZIP_CODE] ok"),
    ("CA 94107-1234", "[ZIP_CODE]"),
    ("lat 82.98635 long 23.140745", "lat [GEO_COORDINATE] long [GEO_COORDINATE]"),
    ("meet at 40.7128, -74.0060", "meet at [GEO_COORDINATE]"),
    ("the account number is 59207220.", "the account number is [ACCOUNT_NUMBER]."),
    ("acct # 0012-3456-7890", "acct # [ACCOUNT_NUMBER]"),
    ("the account number for the bill is 48213907.", "the account number for the bill is [ACCOUNT_NUMBER]."),
    ("my name is Maneesh", "my name is [PERSON]"),
    ("Hello, I'm Priya Raman here", "Hello, I'm [PERSON] here"),
])
def test_new_detectors(text, expected):
    assert R.redact(text).payload == expected


def test_location_links_the_rest_of_the_string():
    out = R.redact("Office at 12 Elm Rd; zip 90210; pin 34.0901 in IL").payload
    for raw in ["12 Elm", "90210", "34.0901", "IL"]:
        assert raw not in out


def test_adjacent_location_parts_merge_into_one_address():
    assert R.redact("I live at 145 Main St, NJ 07922.").payload == "I live at [ADDRESS]."


@pytest.mark.parametrize("text", [
    "Version 1.2.3 costs $19.99, order 12345 shipped, pi is 3.14159",
    "I am Happy to help, OK?",
    "This is Monday's report: 42 items, 98.6 percent done",
    "It's a 5 minute drive, then 3 days on the road",
    "it took long, about 12.75 hours",
])
def test_no_location_means_no_aggressive_rules(text):
    assert R.redact(text).payload == text


@pytest.mark.parametrize("text,raw", [
    ("long its 23.140745. Next", "23.140745"),
    ("at 40.7128, -74.0060.", "40.7128"),
    ("Lives at 12 Elm Rd; zip 90210.", "90210"),
    ("Lives at 12 Elm Rd, pin 34.0901.", "34.0901"),
])
def test_sentence_ending_period_does_not_hide_numbers(text, raw):
    assert raw not in R.redact(text).payload
