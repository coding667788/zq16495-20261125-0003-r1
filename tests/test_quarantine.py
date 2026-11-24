import unittest

from keychronicle.engine import audit_bundle
try:
    from tests._util import T, fixture_bundle, result_map
except ImportError:  # running the file directly
    from _util import T, fixture_bundle, result_map


class QuarantineKnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.bundle = fixture_bundle("quarantine")

    def test_before_publication_reviews_see_valid_signatures(self):
        report = audit_bundle(self.bundle, T, "2026-01-14T00:00:00Z")
        results = result_map(report)
        self.assertEqual(results["Q-CLEAR"]["decision"], "trusted")
        self.assertEqual(results["Q-CONFIRM"]["decision"], "trusted")

    def test_early_public_quarantine_is_uncertain_not_rejected(self):
        report = audit_bundle(self.bundle, T, "2026-01-20T00:00:00Z")
        results = result_map(report)
        self.assertEqual(results["Q-CLEAR"]["decision"], "quarantined")
        self.assertEqual(results["Q-CLEAR"]["status"], "uncertain")
        self.assertEqual(results["Q-CLEAR"]["reason_code"], "quarantined_witness")
        self.assertIn("alice", results["Q-CLEAR"]["uncertainty"]["issuer_ids"])

        sig = next(
            s
            for s in report["signature_reports"]
            if s["signature_id"] == "sig-Q-CLEAR-alice"
        )
        self.assertEqual(sig["status"], "quarantined")
        self.assertTrue(sig["hmac_valid"])

    def test_later_clearance_restores_witness_while_revocation_rejects(self):
        report = audit_bundle(self.bundle, T, "2026-02-10T00:00:00Z")
        results = result_map(report)
        self.assertEqual(results["Q-CLEAR"]["decision"], "trusted")
        self.assertEqual(results["Q-CONFIRM"]["decision"], "rejected")
        self.assertEqual(
            results["Q-CONFIRM"]["rejection"]["evidence_id"],
            "rev-q-confirm-approval",
        )


if __name__ == "__main__":
    unittest.main()
