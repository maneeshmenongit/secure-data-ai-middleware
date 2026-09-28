import sys

import pytest

from datasec.crypto import LocalKeyProvider, Sealed, seal, unseal
from datasec.errors import DataSecError


def test_seal_roundtrip():
    p = LocalKeyProvider()
    value = {"api_key": "sk-test-FAKE-123", "n": 1}
    sealed = seal(p, value)
    assert isinstance(sealed, Sealed)
    assert "sk-test-FAKE-123" not in sealed.token
    assert unseal(p, sealed) == value


def test_key_rotation_keeps_old_ciphertext_readable():
    p = LocalKeyProvider()
    old = seal(p, "first")
    p.add_key("k2")
    new = seal(p, "second")
    assert p.current_key_id() == "k2"
    assert (old.key_id, new.key_id) == ("k1", "k2")
    assert unseal(p, old) == "first"
    assert unseal(p, new) == "second"


def test_tampered_token_raises():
    p = LocalKeyProvider()
    sealed = seal(p, "x")
    forged = Sealed(sealed.key_id, sealed.token[:-4] + "AAAA")
    with pytest.raises(DataSecError):
        unseal(p, forged)


def test_other_providers_key_cannot_decrypt():
    with pytest.raises(DataSecError):
        unseal(LocalKeyProvider(), seal(LocalKeyProvider(), "x"))


def test_missing_cryptography_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography.fernet", None)
    with pytest.raises(DataSecError, match="datasec\\[crypto\\]"):
        LocalKeyProvider()


def test_checkpoint_token_cannot_be_unsealed_as_a_value():
    p = LocalKeyProvider()
    raw = p.encrypt(b'{"a":1}', key_id=p.current_key_id()).decode("ascii")
    with pytest.raises(DataSecError):
        unseal(p, Sealed(p.current_key_id(), raw))
