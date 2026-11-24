from __future__ import annotations

import base64
import hmac
import secrets
from typing import Any

from .canonical import signing_message


def key_bytes(key: dict[str, Any]) -> bytes:
    if key.get("secret_hex") is not None:
        try:
            return bytes.fromhex(str(key["secret_hex"]))
        except ValueError as exc:
            raise ValueError(f"key {key.get('key_id')!r} has invalid secret_hex") from exc
    secret = key.get("secret", key.get("key_material"))
    if secret is None:
        raise ValueError(f"key {key.get('key_id')!r} has neither secret nor secret_hex")
    return str(secret).encode("utf-8")


def sign_approval_bytes(
    approval: dict[str, Any], issued_at: str, key: dict[str, Any]
) -> bytes:
    return hmac.new(key_bytes(key), signing_message(approval, issued_at), "sha256").digest()


def sign_approval(approval: dict[str, Any], issued_at: str, key: dict[str, Any]) -> str:
    return sign_approval_bytes(approval, issued_at, key).hex()


def _base64_candidates(value: str) -> list[bytes]:
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    candidates = []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(decoder(padded, validate=False))
        except (ValueError, TypeError):
            pass
    return candidates


def verify_signature(
    approval: dict[str, Any],
    issued_at: str,
    key: dict[str, Any],
    expected: str,
) -> bool:
    try:
        actual_bytes = sign_approval_bytes(approval, issued_at, key)
    except (ValueError, TypeError):
        return False
    supplied = str(expected or "").strip()
    if not supplied:
        return False
    if hmac.compare_digest(supplied.lower(), actual_bytes.hex()):
        return True
    try:
        supplied_bytes = bytes.fromhex(supplied)
        if hmac.compare_digest(supplied_bytes, actual_bytes):
            return True
    except ValueError:
        pass
    for decoded in _base64_candidates(supplied):
        if hmac.compare_digest(decoded, actual_bytes):
            return True
    return False


def new_sample_key_hex(byte_count: int = 32) -> str:
    """Synthetic offline key material; never randomness from wall time."""
    return secrets.token_hex(byte_count)
