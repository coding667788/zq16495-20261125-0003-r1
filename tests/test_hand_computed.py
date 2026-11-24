import hashlib
import hmac
import json
import unittest

from keychronicle.canonical import signing_message
from keychronicle.crypto import sign_approval
from keychronicle.engine import audit_bundle
try:
    from tests._util import FIXTURES, T, fixture_bundle, result_map
except ImportError:  # running the file directly
    from _util import FIXTURES, T, fixture_bundle, result_map


class HandComputedFixtureTests(unittest.TestCase):
    def test_readme_hmac_constant_is_stable(self):
        approval = {
            "id": "HM-1",
            "issued_at": T,
            "payload": {"amount": 7, "action": "readme-hand-calc"},
        }
        message = signing_message(approval, T)
        self.assertEqual(
            hashlib.sha256(
                (
                    b'{"id":"HM-1","issued_at":"2026-01-10T00:00:00Z",'
                    b'"payload":{"action":"readme-hand-calc","amount":7},'
                    b'"requires":[]}'
                )
            ).hexdigest(),
            "d393986e29ed83b52d02b3860573e7c070f64707305b1ecbf69d43360cef589c",
        )
        mac = hmac.new(b"manual-sample-secret", message, hashlib.sha256).hexdigest()
        self.assertEqual(
            mac,
            "e429776e780d6c86bff26bfc4c6871e11efd18f24a55fb066a44e7d54c8232df",
        )
        self.assertEqual(
            sign_approval(approval, T, {"secret": "manual-sample-secret"}), mac
        )

    def test_manual_fixture_audits_trusted(self):
        bundle = fixture_bundle("manual")
        report = audit_bundle(bundle, T, "2026-02-01T00:00:00Z")
        results = result_map(report)
        self.assertEqual(results["HM-1"]["decision"], "trusted")
        self.assertEqual(len(results["HM-1"]["minimal_witness"]["issuer_ids"]), 2)
        # Fixture JSON itself contains the pinned hand-computed value.
        raw = json.loads((FIXTURES / "manual" / "bundle.json").read_text(encoding="utf-8"))
        manual_sig = next(s for s in raw["signatures"] if s["id"] == "sig-hm-1-manual")
        self.assertEqual(
            manual_sig["hmac"],
            "e429776e780d6c86bff26bfc4c6871e11efd18f24a55fb066a44e7d54c8232df",
        )


if __name__ == "__main__":
    unittest.main()
