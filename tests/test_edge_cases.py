import unittest

from keychronicle.engine import audit_bundle

T = "2026-01-10T00:00:00Z"
KEY = {
    "key_id": "k1",
    "issuer_id": "alice",
    "secret": "unit-secret",
    "valid_from": "2024-01-01T00:00:00Z",
    "valid_to": "2028-01-01T00:00:00Z",
}


class EvidenceEdgeCaseTests(unittest.TestCase):
    def test_bad_hmac_is_an_exact_signature_failure_but_approval_is_insufficient(self):
        bundle = {
            "threshold": 1,
            "keys": [KEY],
            "approvals": [{"id": "A", "issued_at": T, "payload": {"v": 1}}],
            "signatures": [
                {
                    "id": "bad-sig",
                    "approval_id": "A",
                    "issuer_id": "alice",
                    "key_id": "k1",
                    "hmac": "00" * 32,
                }
            ],
        }
        report = audit_bundle(bundle, T, "2026-02-01T00:00:00Z")
        approval = report["approvals"][0]
        signature = report["signature_reports"][0]
        self.assertFalse(signature["hmac_valid"])
        self.assertEqual(signature["status"], "invalid_hmac")
        self.assertEqual(approval["decision"], "inconclusive")
        self.assertEqual(approval["classification"], "insufficient_evidence")

    def test_missing_reference_is_information_gap(self):
        bundle = {
            "threshold": 1,
            "keys": [KEY],
            "approvals": [
                {
                    "id": "CHILD",
                    "issued_at": T,
                    "requires": ["GHOST"],
                    "payload": {},
                }
            ],
            "signatures": [],
        }
        report = audit_bundle(bundle, T, "2026-02-01T00:00:00Z")
        child = report["approvals"][0]
        self.assertEqual(child["decision"], "inconclusive")
        self.assertIn(child["reason_code"], {"dependency_unproven", "below_threshold"})

    def test_empty_bundle_report_is_valid_zero_state(self):
        report = audit_bundle(
            {"approvals": [], "threshold": 2}, T, "2026-02-01T00:00:00Z"
        )
        self.assertEqual(report["summary"]["total_approvals"], 0)
        self.assertEqual(report["approvals"], [])


if __name__ == "__main__":
    unittest.main()
