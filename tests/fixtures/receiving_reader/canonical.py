"""Strict canonical JSON helpers for signed Daimon Matrix artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalError(ValueError):
    """Raised when a value is outside the canonical artifact data model."""


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -(2**53) + 1 <= value <= 2**53 - 1:
            raise CanonicalError("integer is outside the I-JSON exact range")
        return value
    if isinstance(value, float):
        raise CanonicalError("floating-point values are forbidden in V1 artifacts")
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if normalized != value:
            raise CanonicalError("strings must already be NFC-normalized")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalError("lone Unicode surrogates are forbidden")
        return value
    if isinstance(value, Mapping):
        normalized_items: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("object keys must be strings")
            normalized_key = _normalize(key)
            if normalized_key in normalized_items:
                raise CanonicalError("duplicate normalized object key")
            normalized_items[normalized_key] = _normalize(item)
        return {
            key: normalized_items[key]
            for key in sorted(
                normalized_items, key=lambda item: item.encode("utf-16be")
            )
        }
    if isinstance(value, Sequence) and not isinstance(
        value, (bytes, bytearray, memoryview)
    ):
        return [_normalize(item) for item in value]
    raise CanonicalError(f"unsupported canonical value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return RFC-8785-compatible bytes for the integer-only V1 data model."""

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")


def b64url(data: bytes) -> str:
    """Encode unpadded RFC 4648 base64url."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(value: str, *, length: int | None = None) -> bytes:
    """Decode canonical unpadded base64url and optionally require a length."""

    if not isinstance(value, str) or "=" in value:
        raise CanonicalError("base64url must be an unpadded string")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as error:
        raise CanonicalError("invalid base64url") from error
    if b64url(raw) != value:
        raise CanonicalError("non-canonical base64url")
    if length is not None and len(raw) != length:
        raise CanonicalError(f"decoded value must be {length} bytes")
    return raw


def domain_bytes(domain: str, body: Mapping[str, Any]) -> bytes:
    """Build a domain-separated signing preimage."""

    return domain.encode("ascii") + b"\x00" + canonical_bytes(body)


def digest(domain: str, body: Mapping[str, Any]) -> bytes:
    """Hash one domain-separated canonical body."""

    return hashlib.sha256(domain_bytes(domain, body)).digest()
