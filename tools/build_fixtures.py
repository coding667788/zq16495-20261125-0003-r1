"""Deterministically assemble the checked-in hand-shaped JSON fixtures.

The HMAC values are computed with the same standard-library primitives used by
keychronicle.  A separate test pins one exact HMAC constant so the signed
message format remains hand-reproducible.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from keychronicle.crypto import sign_approval  # noqa: E402
from keychronicle.engine import checkpoint_digest  # noqa: E402

T = "2026-01-10T00:00:00Z"
VALID_FROM = "2024-01-01T00:00:00Z"
VALID_TO = "2028-01-01T00:00:00Z"


def sample_key(key_id: str, issuer: str, secret: str | None = None) -> dict[str, Any]:
    return {
        "key_id": key_id,
        "issuer_id": issuer,
        "algorithm": "HMAC-SHA256",
        "secret": secret or f"sample-secret-{key_id}",
        "valid_from": VALID_FROM,
        "valid_to": VALID_TO,
    }


STANDARD_KEYS = [
    sample_key("alice-key", "alice"),
    sample_key("bob-key", "bob"),
    sample_key("carol-key", "carol"),
    sample_key("dave-key", "dave"),
    sample_key("issuer-a-key", "issuer-a"),
    sample_key("issuer-b-key", "issuer-b"),
]


def new_bundle(threshold: int = 2) -> dict[str, Any]:
    return {
        "schema_version": "keychronicle-bundle/1",
        "threshold": threshold,
        "issued_at": T,
        "keys": [dict(key) for key in STANDARD_KEYS],
        "approvals": [],
        "signatures": [],
        "quarantines": [],
        "clearances": [],
        "revocations": [],
        "checkpoints": [],
    }


def add_approval(
    bundle: dict[str, Any],
    approval_id: str,
    *,
    requires: list[str] | None = None,
    terminal: bool | None = None,
    issuers: list[str] | tuple[str, ...] = ("alice", "bob"),
    issued_at: str = T,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    approval: dict[str, Any] = {
        "id": approval_id,
        "issued_at": issued_at,
        "payload": payload or {"document": approval_id, "classification": "internal"},
    }
    if requires:
        approval["requires"] = requires
    if terminal is not None:
        approval["terminal"] = terminal
    bundle["approvals"].append(approval)

    for issuer in issuers:
        key_id = f"{issuer}-key"
        key = next((k for k in bundle["keys"] if k["key_id"] == key_id), None)
        if key is None:
            key = sample_key(key_id, issuer)
            bundle["keys"].append(key)
        signature_id = f"sig-{approval_id}-{issuer}"
        bundle["signatures"].append(
            {
                "id": signature_id,
                "approval_id": approval_id,
                "issuer_id": issuer,
                "key_id": key_id,
                "algorithm": "HMAC-SHA256",
                "signed_at": issued_at,
                "hmac": sign_approval(approval, issued_at, key),
            }
        )
    return approval


def add_custom_signature(
    bundle: dict[str, Any],
    approval_id: str,
    signature_id: str,
    issuer: str,
    key_id: str,
    *,
    signed_at: str = T,
) -> None:
    approval = next(a for a in bundle["approvals"] if a["id"] == approval_id)
    key = next(k for k in bundle["keys"] if k["key_id"] == key_id)
    bundle["signatures"].append(
        {
            "id": signature_id,
            "approval_id": approval_id,
            "issuer_id": issuer,
            "key_id": key_id,
            "algorithm": "HMAC-SHA256",
            "signed_at": signed_at,
            "hmac": sign_approval(approval, signed_at, key),
        }
    )


def write_bundle(relative: str, bundle: dict[str, Any]) -> None:
    directory = ROOT / "fixtures" / relative
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "bundle.json"
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


def build_manual() -> None:
    bundle = new_bundle(2)
    bundle["keys"].append(
        {
            "key_id": "manual-key",
            "issuer_id": "manual-issuer",
            "algorithm": "HMAC-SHA256",
            "secret": "manual-sample-secret",
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_to": "2027-01-01T00:00:00Z",
        }
    )
    approval = {
        "id": "HM-1",
        "issued_at": T,
        "payload": {"amount": 7, "action": "readme-hand-calc"},
    }
    bundle["approvals"].append(approval)
    bundle["signatures"].append(
        {
            "id": "sig-hm-1-manual",
            "approval_id": "HM-1",
            "issuer_id": "manual-issuer",
            "key_id": "manual-key",
            "hmac": "e429776e780d6c86bff26bfc4c6871e11efd18f24a55fb066a44e7d54c8232df",
        }
    )
    add_custom_signature(bundle, "HM-1", "sig-hm-1-bob", "bob", "bob-key")
    write_bundle("manual", bundle)


def build_rotation() -> None:
    bundle = new_bundle(2)
    bundle["keys"].extend(
        [
            {
                "key_id": "alice-old-2024",
                "issuer_id": "alice",
                "secret": "rotation-old-secret-one",
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_to": "2027-01-01T00:00:00Z",
            },
            {
                "key_id": "alice-old-2025",
                "issuer_id": "alice",
                "secret": "rotation-old-secret-two",
                "valid_from": "2025-06-01T00:00:00Z",
                "valid_to": "2028-01-01T00:00:00Z",
            },
        ]
    )
    add_approval(bundle, "ROT-ONE-ISSUER", issuers=[])
    add_custom_signature(
        bundle, "ROT-ONE-ISSUER", "sig-rot-old-1", "alice", "alice-old-2024"
    )
    add_custom_signature(
        bundle, "ROT-ONE-ISSUER", "sig-rot-old-2", "alice", "alice-old-2025"
    )

    add_approval(bundle, "ROT-WITH-BOB", issuers=[])
    add_custom_signature(
        bundle, "ROT-WITH-BOB", "sig-rot-bob-old-1", "alice", "alice-old-2024"
    )
    add_custom_signature(
        bundle, "ROT-WITH-BOB", "sig-rot-bob-old-2", "alice", "alice-old-2025"
    )
    add_custom_signature(bundle, "ROT-WITH-BOB", "sig-rot-bob", "bob", "bob-key")
    write_bundle("rotation_quorum", bundle)


def build_quarantine() -> None:
    bundle = new_bundle(2)
    add_approval(bundle, "Q-CLEAR", issuers=["alice", "bob"])
    add_approval(bundle, "Q-CONFIRM", issuers=["carol", "dave"])
    bundle["quarantines"] = [
        {
            "id": "q-alice-jan",
            "target_type": "signature",
            "target_id": "sig-Q-CLEAR-alice",
            "start_at": "2026-01-09T00:00:00Z",
            "end_at": "2026-01-12T00:00:00Z",
            "published_at": "2026-01-15T00:00:00Z",
            "reason": "unexpected rotation from alice endpoint",
        },
        {
            "id": "q-carol-jan",
            "target_type": "signature",
            "target_id": "sig-Q-CONFIRM-carol",
            "start_at": "2026-01-09T00:00:00Z",
            "end_at": "2026-01-12T00:00:00Z",
            "published_at": "2026-01-16T00:00:00Z",
            "reason": "possible key disclosure",
        },
    ]
    bundle["clearances"] = [
        {
            "id": "clear-alice",
            "quarantine_id": "q-alice-jan",
            "target_type": "signature",
            "target_id": "sig-Q-CLEAR-alice",
            "published_at": "2026-02-01T00:00:00Z",
            "at": "2026-01-31T12:00:00Z",
            "reason": "HSM audit proves rotation was scheduled",
        }
    ]
    bundle["revocations"] = [
        {
            "id": "rev-q-confirm-approval",
            "target_type": "approval",
            "target_id": "Q-CONFIRM",
            "effective_at": "2026-01-01T00:00:00Z",
            "published_at": "2026-02-02T00:00:00Z",
            "reason": "key disclosure confirmed; approval backdated into compromise window",
        }
    ]
    write_bundle("quarantine", bundle)


def build_revocation_shared() -> None:
    bundle = new_bundle(2)
    graph = {
        "ROOT": [],
        "SHARED": ["ROOT"],
        "SHORT": ["SHARED"],
        "LONG_1": ["SHARED"],
        "LONG_2": ["LONG_1"],
        "TERMINAL_DIRECT": ["SHARED"],
        "TERMINAL_MULTI": ["SHORT", "LONG_2"],
    }
    for approval_id, requires in graph.items():
        terminal = approval_id.startswith("TERMINAL_")
        add_approval(
            bundle,
            approval_id,
            requires=requires,
            terminal=terminal,
            issuers=["issuer-a", "issuer-b"],
        )
    bundle["revocations"] = [
        {
            "id": "rev-root-retroactive",
            "target_type": "approval",
            "target_id": "ROOT",
            "effective_at": "2025-12-15T00:00:00Z",
            "published_at": "2026-01-25T00:00:00Z",
            "reason": "ROOT signer key was compromised before the archived issuance",
        }
    ]
    write_bundle("revocation_shared", bundle)


def build_cycle_checkpoint() -> None:
    bundle = new_bundle(2)
    add_approval(bundle, "RING_A", requires=["RING_B"], issuers=["alice", "bob"])
    add_approval(bundle, "RING_B", requires=["RING_C"], issuers=["alice", "carol"])
    add_approval(bundle, "RING_C", requires=["RING_A"], issuers=["bob", "carol"])

    add_approval(bundle, "LOCK_X", requires=["LOCK_Y"], issuers=["alice", "bob"])
    add_approval(bundle, "LOCK_Y", requires=["LOCK_X"], issuers=["carol", "dave"])
    checkpoint = {
        "id": "cp-lock-x-frozen",
        "approval_id": "LOCK_X",
        "decision": "trusted",
        "frozen_at": "2026-01-12T00:00:00Z",
        "published_at": "2026-01-12T00:00:00Z",
        "witness": {
            "source": "independent-review-board",
            "independent_issuer_count": 2,
            "signature_ids": ["sig-LOCK_X-alice", "sig-LOCK_X-bob"],
        },
    }
    checkpoint["digest"] = "sha256:" + checkpoint_digest(checkpoint)
    bundle["checkpoints"].append(checkpoint)
    write_bundle("cycle_checkpoint", bundle)


def main() -> None:
    build_manual()
    build_rotation()
    build_quarantine()
    build_revocation_shared()
    build_cycle_checkpoint()


if __name__ == "__main__":
    main()
