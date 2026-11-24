from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keychronicle.loader import load_bundle  # noqa: E402

FIXTURES = ROOT / "fixtures"
T = "2026-01-10T00:00:00Z"


def fixture_bundle(name: str):
    return load_bundle(FIXTURES / name / "bundle.json")


def result_map(report):
    return {item["approval_id"]: item for item in report["approvals"]}
