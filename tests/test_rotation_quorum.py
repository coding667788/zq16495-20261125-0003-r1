import unittest

from keychronicle.engine import audit_bundle
try:
    from tests._util import T, fixture_bundle, result_map
except ImportError:  # running the file directly
    from _util import T, fixture_bundle, result_map


class RotationQuorumTests(unittest.TestCase):
    def setUp(self):
        self.report = audit_bundle(
            fixture_bundle("rotation_quorum"), T, "2026-02-01T00:00:00Z"
        )
        self.results = result_map(self.report)

    def test_two_overlapping_old_keys_from_one_issuer_are_one_vote(self):
        result = self.results["ROT-ONE-ISSUER"]
        self.assertEqual(result["independent_issuer_count"], 1)
        self.assertEqual(result["decision"], "inconclusive")
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual(result["classification"], "insufficient_evidence")
        self.assertIsNone(result["minimal_witness"])
        all_ids = {s["signature_id"] for s in self.report["signature_reports"]}
        self.assertIn("sig-rot-old-1", all_ids)
        self.assertIn("sig-rot-old-2", all_ids)
        old_ids = {"sig-rot-old-1", "sig-rot-old-2"}
        old_reports = [
            s for s in self.report["signature_reports"] if s["signature_id"] in old_ids
        ]
        self.assertTrue(all(s["time_valid"] and s["hmac_valid"] for s in old_reports))
        self.assertEqual({s["issuer_id"] for s in old_reports}, {"alice"})

    def test_second_independent_issuer_reaches_minimal_two_signature_witness(self):
        result = self.results["ROT-WITH-BOB"]
        self.assertEqual(result["decision"], "trusted")
        witness = result["minimal_witness"]
        self.assertTrue(witness["minimal"])
        self.assertEqual(witness["independent_issuer_count"], 2)
        self.assertEqual(set(witness["issuer_ids"]), {"alice", "bob"})
        self.assertEqual(len(witness["signature_ids"]), 2)
        # The second Alice key is an alternate key from the same issuer and is
        # deliberately absent from the minimum witness.
        self.assertNotIn("sig-rot-bob-old-2", witness["signature_ids"])


if __name__ == "__main__":
    unittest.main()
