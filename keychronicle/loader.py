from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import BundleError

_COLLECTION_FILES = {
    "keys": ("keys.json",),
    "approvals": ("approvals.json",),
    "signatures": ("signatures.json",),
    "quarantines": ("quarantines.json", "quarantine_notices.json"),
    "clearances": ("clearances.json",),
    "revocations": ("revocations.json", "revocation_notices.json"),
    "checkpoints": ("checkpoints.json", "trust_checkpoints.json"),
}


def _read_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise BundleError(f"bundle path does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BundleError(f"invalid UTF-8 JSON in {path}: {exc}") from exc


def _as_list(value: Any, field: str, source: Path) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict) and field in value:
        value = value[field]
    if not isinstance(value, list):
        raise BundleError(f"{source}: {field} must be a JSON array")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise BundleError(f"{source}: {field}[{index}] must be an object")
    return value


def load_bundle(path_str: str | Path) -> dict[str, Any]:
    """Load a single bundle JSON file or a directory of UTF-8 JSON files."""
    path = Path(path_str)
    if not path.exists():
        raise BundleError(f"bundle path does not exist: {path}")

    if path.is_file():
        bundle = _read_json(path)
        if not isinstance(bundle, dict):
            raise BundleError("bundle JSON root must be an object")
        _validate_collections(bundle, path)
        bundle.setdefault("_source_path", str(path))
        return bundle

    bundle_path = path / "bundle.json"
    if bundle_path.exists():
        bundle = _read_json(bundle_path)
        if not isinstance(bundle, dict):
            raise BundleError("bundle.json root must be an object")
        _validate_collections(bundle, bundle_path)
    else:
        bundle = {}
        for field, filenames in _COLLECTION_FILES.items():
            for filename in filenames:
                candidate = path / filename
                if candidate.exists():
                    bundle[field] = _as_list(_read_json(candidate), field, candidate)
                    break
        policy_path = path / "policy.json"
        if policy_path.exists():
            policy = _read_json(policy_path)
            if not isinstance(policy, dict):
                raise BundleError("policy.json must be an object")
            bundle["policy"] = policy

    _validate_collections(bundle, path)
    bundle["_source_path"] = str(path)
    return bundle


def _validate_collections(bundle: dict[str, Any], source: Path) -> None:
    for field in _COLLECTION_FILES:
        if field not in bundle or bundle[field] is None:
            bundle[field] = []
        if not isinstance(bundle[field], list):
            raise BundleError(f"{source}: {field} must be an array")

    approvals = bundle["approvals"]
    seen: set[str] = set()
    for index, approval in enumerate(approvals):
        if not isinstance(approval, dict):
            raise BundleError(f"approvals[{index}] must be an object")
        approval_id = approval.get("id")
        if not isinstance(approval_id, str) or not approval_id:
            raise BundleError(f"approvals[{index}].id must be a non-empty string")
        if approval_id in seen:
            raise BundleError(f"duplicate approval id: {approval_id}")
        seen.add(approval_id)

    for field in ("signatures", "keys", "revocations", "quarantines", "clearances", "checkpoints"):
        for index, item in enumerate(bundle[field]):
            if not isinstance(item, dict):
                raise BundleError(f"{field}[{index}] must be an object")


def index_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Build stable in-memory indexes without mutating the input bundle."""
    approvals_by_id = {a["id"]: a for a in bundle["approvals"]}
    keys_by_id: dict[str, dict[str, Any]] = {}
    for key in bundle.get("keys", []):
        key_id = key.get("key_id") or key.get("id")
        if not key_id:
            raise BundleError("every key needs key_id")
        key = dict(key)
        key["key_id"] = key_id
        keys_by_id[key_id] = key

    requires: dict[str, list[str]] = {}
    dependents: dict[str, list[str]] = {approval_id: [] for approval_id in approvals_by_id}
    # Missing references insert synthetic nodes, so iterate a stable snapshot.
    for approval_id, approval in list(approvals_by_id.items()):
        raw = (
            approval.get("requires")
            if approval.get("requires") is not None
            else approval.get(
                "references",
                approval.get(
                    "prerequisites",
                    approval.get("depends_on", approval.get("refs", [])),
                ),
            )
        )
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise BundleError(f"approval {approval_id}: requires/references must be an array")
        missing = [ref for ref in raw if ref not in approvals_by_id]
        if missing:
            # Missing references are represented as information gaps rather
            # than crashing an audit; keep the id and add a synthetic marker.
            for ref in missing:
                approvals_by_id.setdefault(
                    ref,
                    {"id": ref, "_missing": True, "requires": [], "payload": {}},
                )
                dependents.setdefault(ref, [])
        refs = sorted(set(str(ref) for ref in raw))
        requires[approval_id] = refs
        for ref in refs:
            dependents.setdefault(ref, [])
            if approval_id not in dependents[ref]:
                dependents[ref].append(approval_id)

    for missing_id, approval in list(approvals_by_id.items()):
        if approval.get("_missing"):
            requires.setdefault(missing_id, [])

    for values in dependents.values():
        values.sort()

    terminal_ids = _terminal_ids(bundle, approvals_by_id, dependents)
    return {
        "approvals_by_id": approvals_by_id,
        "keys_by_id": keys_by_id,
        "requires": requires,
        "dependents": dependents,
        "terminal_ids": terminal_ids,
    }


def _terminal_ids(
    bundle: dict[str, Any],
    approvals_by_id: dict[str, dict[str, Any]],
    dependents: dict[str, list[str]],
) -> list[str]:
    policy = bundle.get("policy") if isinstance(bundle.get("policy"), dict) else {}
    explicit = set(policy.get("terminal_ids", []))
    for approval_id, approval in approvals_by_id.items():
        if approval.get("terminal") is True or approval.get("is_terminal") is True:
            explicit.add(approval_id)
    # Graph sinks in propagation direction: nobody derives from them.
    sinks = {
        approval_id
        for approval_id in approvals_by_id
        if not dependents.get(approval_id) and not approvals_by_id[approval_id].get("_missing")
    }
    return sorted(explicit | sinks)
