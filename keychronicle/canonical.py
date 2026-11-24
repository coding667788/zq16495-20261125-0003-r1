from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Deterministic UTF-8 JSON used for digests and HMAC signatures."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def payload_digest(approval: dict[str, Any]) -> str:
    payload = approval.get("payload", approval)
    return sha256_hex(canonical_bytes(payload))


SIGNING_DOMAIN = "keychronicle-hmac-sha256/v1"


def signed_content(approval: dict[str, Any], issued_at: str) -> dict[str, Any]:
    """Canonical approval content bound by every HMAC.

    References are included so a dependency edge cannot be edited without
    invalidating the signatures.
    """
    references = (
        approval.get("requires")
        or approval.get("references")
        or approval.get("prerequisites")
        or approval.get("depends_on")
        or approval.get("refs")
        or []
    )
    return {
        "id": approval["id"],
        "issued_at": issued_at,
        "payload": approval.get("payload", {}),
        "requires": sorted(str(ref) for ref in references),
    }


def content_digest(approval: dict[str, Any], issued_at: str) -> str:
    return sha256_hex(canonical_bytes(signed_content(approval, issued_at)))


def signing_message(approval: dict[str, Any], issued_at: str) -> bytes:
    """The small, hand-reproducible signed message.

    It binds the domain, approval id, issuance instant and a digest of the
    canonical signed content.  README works an example by hand.
    """
    lines = [
        SIGNING_DOMAIN,
        str(approval["id"]),
        issued_at,
        content_digest(approval, issued_at),
    ]
    return "\n".join(lines).encode("ascii")
