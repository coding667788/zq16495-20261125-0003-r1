import unittest

from keychronicle.diff import diff_knowledge_cuts
from keychronicle.engine import audit_bundle
try:
    from tests._util import T, fixture_bundle, result_map
except ImportError:  # running the file directly
    from _util import T, fixture_bundle, result_map


class RevocationSharedPropagationTests(unittest.TestCase):
    def setUp(self):
        self.bundle = fixture_bundle("revocation_shared")
        self.early_k = "2026-01-20T00:00:00Z"
        self.late_k = "2026-02-01T00:00:00Z"
        self.diff = diff_knowledge_cuts(
            self.bundle, T, self.early_k, self.late_k
        )

    def test_all_shared_graph_is_trusted_before_publication(self):
        report = audit_bundle(self.bundle, T, self.early_k)
        self.assertEqual(report["summary"]["trusted"], 7)

    def test_revocation_propagates_multiple_levels_through_shared_approval(self):
        report = audit_bundle(self.bundle, T, self.late_k)
        results = result_map(report)
        for approval_id in (
            "ROOT",
            "SHARED",
            "SHORT",
            "LONG_1",
            "LONG_2",
            "TERMINAL_DIRECT",
            "TERMINAL_MULTI",
        ):
            self.assertEqual(results[approval_id]["decision"], "rejected", approval_id)
        self.assertEqual(results["SHARED"]["rejection"]["code"], "dependency_rejected")

    def test_diff_lists_root_failure_and_all_terminal_approvals(self):
        root = next(
            f for f in self.diff["first_failures"] if f["edge_id"] == "validity:ROOT"
        )
        self.assertEqual(root["causal_class"], "direct_evidence")
        self.assertEqual(root["evidence_ids"], ["rev-root-retroactive"])
        self.assertEqual(
            root["affected_terminal_ids"],
            ["TERMINAL_DIRECT", "TERMINAL_MULTI"],
        )
        self.assertEqual(
            self.diff["affected_terminal_ids"],
            ["TERMINAL_DIRECT", "TERMINAL_MULTI"],
        )

    def test_same_terminal_multiple_routes_uses_shortest_evidenced_path(self):
        change = next(
            c for c in self.diff["terminal_changes"] if c["terminal_id"] == "TERMINAL_MULTI"
        )
        explanation = change["best_explanation"]
        self.assertEqual(
            explanation["path_approvals"],
            ["ROOT", "SHARED", "SHORT", "TERMINAL_MULTI"],
        )
        self.assertEqual(explanation["hops"], 3)
        self.assertEqual(
            explanation["path_edges"],
            [
                "reference:SHARED->ROOT",
                "reference:SHORT->SHARED",
                "reference:TERMINAL_MULTI->SHORT",
            ],
        )
        self.assertGreaterEqual(explanation["alternative_explanation_count"], 1)

        direct = next(
            c for c in self.diff["terminal_changes"] if c["terminal_id"] == "TERMINAL_DIRECT"
        )
        self.assertEqual(
            direct["best_explanation"]["path_approvals"],
            ["ROOT", "SHARED", "TERMINAL_DIRECT"],
        )


if __name__ == "__main__":
    unittest.main()
