import os
import time
import unittest
from unittest.mock import patch

from keychronicle.crypto import sign_approval
from keychronicle.engine import AuditEngine

N = int(os.environ.get("KEYCHRONICLE_PERF_N", "100000"))


@unittest.skipIf(
    os.environ.get("KEYCHRONICLE_SKIP_PERF") == "1",
    "set KEYCHRONICLE_SKIP_PERF=1 to skip the 100k approval performance test",
)
class HundredThousandApprovalPerformanceTests(unittest.TestCase):
    def build_chain(self, count):
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
            approval_id = f"P{i:06d}"
            approval = {"id": approval_id, "issued_at": issued, "payload": {"i": i}}
            if i:
                approval["requires"] = [f"P{i - 1:06d}"]
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

    def test_each_proof_node_is_resolved_only_once(self):
        bundle = self.build_chain(N)
        engine = AuditEngine(
            bundle, bundle["issued_at"], "2026-02-01T00:00:00Z", threshold=1
        )

        original = AuditEngine._base_result
        calls = 0

        def counting_base_result(self, node, scc_index, members):
            nonlocal calls
            calls += 1
            return original(self, node, scc_index, members)

        started = time.perf_counter()
        with patch.object(AuditEngine, "_base_result", counting_base_result):
            report = engine.audit(build_edges=False)
        elapsed = time.perf_counter() - started

        self.assertEqual(calls, N)
        self.assertEqual(report["summary"]["trusted"], N)
        self.assertEqual(report["stats"]["proof_nodes_built"], N)
        # A quadratic "re-walk every proven prefix for every approval"
        # implementation cannot finish 100k in a generous 60 second bound.
        self.assertLess(elapsed, 60.0, f"100k audit took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
