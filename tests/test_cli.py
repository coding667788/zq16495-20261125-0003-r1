import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, "-m", "keychronicle", *arguments],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_audit_positional_bundle_and_utf8_json(self):
        report = self.run_cli(
            "audit",
            "fixtures/rotation_quorum/bundle.json",
            "--issued-at",
            "2026-01-10T00:00:00Z",
            "--known-at",
            "2026-02-01T00:00:00Z",
            "--no-signature-reports",
        )
        self.assertEqual(report["schema_version"], "keychronicle.audit/1")
        self.assertEqual(report["summary"]["inconclusive"], 1)

    def test_diff_command(self):
        report = self.run_cli(
            "diff",
            "fixtures/revocation_shared/bundle.json",
            "--issued-at",
            "2026-01-10T00:00:00Z",
            "--from-known-at",
            "2026-01-20T00:00:00Z",
            "--to-known-at",
            "2026-02-01T00:00:00Z",
        )
        self.assertEqual(report["summary"]["changed_terminal_count"], 2)
        self.assertIn("first_failures", report)


if __name__ == "__main__":
    unittest.main()
