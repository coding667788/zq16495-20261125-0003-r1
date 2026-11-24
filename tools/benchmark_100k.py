from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from keychronicle.crypto import sign_approval
from keychronicle.engine import AuditEngine


def build_chain(count: int) -> dict:
    issued = "2026-01-10T00:00:00Z"
    key = {
        "key_id": "bulk-key",
        "issuer_id": "bulk-issuer",
        "secret": "bulk-sample-secret",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_to": "2028-01-01T00:00:00Z",
    }
    approvals = []
    signatures = []
    for i in range(count):
        approval_id = f"A{i:06d}"
        approval = {
            "id": approval_id,
            "issued_at": issued,
            "payload": {"i": i},
        }
        if i:
            approval["requires"] = [f"A{i - 1:06d}"]
        approvals.append(approval)
        signatures.append(
            {
                "id": f"S{i:06d}",
                "approval_id": approval_id,
                "issuer_id": "bulk-issuer",
                "key_id": "bulk-key",
                "hmac": sign_approval(approval, issued, key),
            }
        )
    return {
        "threshold": 1,
        "issued_at": issued,
        "keys": [key],
        "approvals": approvals,
        "signatures": signatures,
    }


def main() -> None:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    started = time.perf_counter()
    bundle = build_chain(count)
    built = time.perf_counter()
    engine = AuditEngine(bundle, bundle["issued_at"], "2026-02-01T00:00:00Z", threshold=1)
    report = engine.audit(build_edges=False)
    audited = time.perf_counter()
    encoded = json.dumps(report, ensure_ascii=False)
    serialized = time.perf_counter()
    print(
        json.dumps(
            {
                "count": count,
                "build_seconds": round(built - started, 3),
                "audit_seconds": round(audited - built, 3),
                "serialize_seconds": round(serialized - audited, 3),
                "json_mb": round(len(encoded.encode("utf-8")) / 1_000_000, 1),
                "summary": report["summary"],
                "stats": report["stats"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
