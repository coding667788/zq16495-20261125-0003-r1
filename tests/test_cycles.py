import unittest

from keychronicle.engine import audit_bundle
try:
    from tests._util import T, fixture_bundle, result_map
except ImportError:  # running the file directly
    from _util import T, fixture_bundle, result_map


class CycleAndCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.report = audit_bundle(
            fixture_bundle("cycle_checkpoint"), T, "2026-02-01T00:00:00Z"
        )
        self.results = result_map(self.report)

    def test_ring_has_stable_canonical_evidence(self):
        ring = next(c for c in self.report["cycles"] if set(c["nodes"]) == {
            "RING_A",
            "RING_B",
            "RING_C",
        })
        self.assertEqual(
            ring["representative_path"],
            ["RING_A", "RING_B", "RING_C", "RING_A"],
        )
        self.assertEqual(
            ring["canonical_path"], "RING_A -> RING_B -> RING_C -> RING_A"
        )
        self.assertTrue(ring["stable_digest"])
        for node in ("RING_A", "RING_B", "RING_C"):
            self.assertEqual(self.results[node]["decision"], "inconclusive")
            self.assertEqual(self.results[node]["reason_code"], "unresolved_reference_cycle")
            self.assertEqual(self.results[node]["cycle_id"], ring["cycle_id"])

    def test_frozen_checkpoint_anchors_and_unlocks_cycle(self):
        self.assertEqual(self.results["LOCK_X"]["decision"], "trusted")
        self.assertEqual(self.results["LOCK_X"]["checkpoint_id"], "cp-lock-x-frozen")
        self.assertEqual(self.results["LOCK_Y"]["decision"], "trusted")
        self.assertIsNone(self.results["LOCK_Y"]["checkpoint_id"])
        self.assertEqual(self.report["summary"]["checkpoint_hits"], 1)


if __name__ == "__main__":
    unittest.main()
