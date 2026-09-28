"""Field-level encryption for secret-labelled values. Optional: pip install 'datasec[crypto]'."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import DataSecError


class KeyProvider(Protocol):
    def encrypt(self, plaintext: bytes, *, key_id: str | None = None) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, key_id: str) -> bytes: ...

    def current_key_id(self) -> str: ...


class LocalKeyProvider:
    """Dev-only Fernet keys held in memory. Rotate with add_key(); old ciphertext
    still decrypts because every Sealed value records the key_id that made it."""

    def __init__(self, keys: dict[str, bytes] | None = None, current: str | None = None) -> None:
        try:
            from cryptography.fernet import Fernet, InvalidToken
        except ImportError as exc:
            raise DataSecError(
                "LocalKeyProvider needs the optional crypto extra: pip install 'datasec[crypto]'"
            ) from exc
        self._fernet = Fernet
        self._invalid = InvalidToken
        self._keys: dict[str, Any] = {}
        for key_id, key in (keys or {"k1": Fernet.generate_key()}).items():
            self._keys[key_id] = Fernet(key)
        self._current = current if current is not None else list(self._keys)[-1]
        if self._current not in self._keys:
            raise ValueError(f"unknown current key id {self._current!r}")

    def add_key(self, key_id: str, key: bytes | None = None, *, make_current: bool = True) -> None:
        self._keys[key_id] = self._fernet(key if key is not None else self._fernet.generate_key())
        if make_current:
            self._current = key_id

    def current_key_id(self) -> str:
        return self._current

    def encrypt(self, plaintext: bytes, *, key_id: str | None = None) -> bytes:
        return self._keys[key_id or self._current].encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, *, key_id: str) -> bytes:
        try:
            return self._keys[key_id].decrypt(ciphertext)
        except (KeyError, self._invalid) as exc:
            raise DataSecError("decryption failed") from exc


@dataclass(frozen=True)
class Sealed:
    """An encrypted value as it should be stored: key id + Fernet token (text)."""

    key_id: str
    token: str


def seal(provider: KeyProvider, value: Any) -> Sealed:
    """JSON-encode then encrypt. Tuples come back as lists and int dict keys as str."""
    key_id = provider.current_key_id()
    plaintext = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Sealed(key_id, provider.encrypt(plaintext, key_id=key_id).decode("ascii"))


def unseal(provider: KeyProvider, sealed: Sealed) -> Any:
    try:
        plaintext = provider.decrypt(sealed.token.encode("ascii"), key_id=sealed.key_id)
    except DataSecError:
        raise
    except Exception as exc:
        raise DataSecError("decryption failed") from exc
    return json.loads(plaintext)
