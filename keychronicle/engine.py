from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from time import perf_counter
from typing import Any

from .canonical import canonical_bytes, sha256_hex
from .crypto import verify_signature
from .errors import BundleError
from .graph import build_cycle_evidence, strongly_connected_components, topological_scc_order
from .loader import index_bundle
from .timeutil import parse_time, visible_at, within_interval

_TARGET_ALIASES = {
    "approval": "approval",
    "approvals": "approval",
    "chit": "approval",
    "qianpi": "approval",
    "签批": "approval",
    "signature": "signature",
    "signatures": "signature",
    "sig": "signature",
    "hmac": "signature",
    "key": "key",
    "keys": "key",
    "issuer": "issuer",
    "issuers": "issuer",
}

_STATUS_RANK = {"trusted": 0, "inconclusive": 1, "quarantined": 2, "rejected": 3}


def normalize_target_type(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _TARGET_ALIASES.get(text, text or "unknown")


def checkpoint_digest(checkpoint: dict[str, Any]) -> str:
    body = {k: v for k, v in checkpoint.items() if k not in {"digest", "digest_algorithm"}}
    return sha256_hex(canonical_bytes(body))


def _first_present(notice: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in notice and notice[name] is not None:
            return notice[name]
    return None


class AuditEngine:
    """Memoized temporal trust evaluator.

    The graph is reduced to SCCs and resolved in prerequisite-first order.
    Each approval is therefore turned into a proof result once; shared
    prerequisites are object references/ids rather than copied subproofs.
    """

    def __init__(
        self,
        bundle: dict[str, Any],
        issued_at: str | datetime,
        known_at: str | datetime,
        *,
        threshold: int | None = None,
        verify_digests: bool = True,
    ) -> None:
        self.bundle = bundle
        self.index = index_bundle(bundle)
        self.approvals_by_id = self.index["approvals_by_id"]
        self.keys_by_id = self.index["keys_by_id"]
        self.requires = self.index["requires"]
        self.dependents = self.index["dependents"]
        self.terminal_ids = self.index["terminal_ids"]

        self.issued_at_dt = self._parse_cli_time(issued_at, "--issued-at")
        self.known_at_dt = self._parse_cli_time(known_at, "--known-at")
        self.issued_at = self.issued_at_dt.isoformat().replace("+00:00", "Z")
        self.known_at = self.known_at_dt.isoformat().replace("+00:00", "Z")

        policy = bundle.get("policy") if isinstance(bundle.get("policy"), dict) else {}
        bundle_threshold = bundle.get("threshold", bundle.get("quorum"))
        policy_threshold = policy.get("threshold", policy.get("quorum", 2))
        self.threshold = int(
            threshold if threshold is not None else bundle_threshold or policy_threshold
        )
        if self.threshold < 1:
            raise BundleError("threshold must be at least 1")
        self.verify_digests = verify_digests

        self.stats = {
            "approvals_evaluated": 0,
            "signature_reports": 0,
            "checkpoint_hits": 0,
            "checkpoints_rejected": 0,
            "proof_nodes_built": 0,
            "dependency_edges": sum(len(v) for v in self.requires.values()),
            "scc_count": 0,
            "cycle_count": 0,
            "internal_propagations": 0,
        }

        self.signature_reports: dict[str, dict[str, Any]] = {}
        self.signatures_by_approval: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.checkpoint_reports: list[dict[str, Any]] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.edge_results: dict[str, dict[str, Any]] = {}
        self.cycles: list[dict[str, Any]] = []
        self.cycle_by_scc: dict[int, str] = {}
        self.components: list[list[str]] = []
        self.scc_id: dict[str, int] = {}
        self.scc_order: list[int] = []
        self.visible_records: dict[str, list[dict[str, Any]]] = {}
        self.notice_index: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.checkpoints_by_approval: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._approval_time_cache: dict[str, tuple[datetime, str]] = {}
        self._key_interval_cache: dict[str, tuple[datetime | None, datetime | None]] = {}
        self._audited = False

    @staticmethod
    def _parse_cli_time(value: str | datetime, flag: str) -> datetime:
        if isinstance(value, datetime):
            parsed = value
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        return parse_time(value, flag)

    def audit(self, *, build_edges: bool = True) -> dict[str, Any]:
        if self._audited:
            return self.public_report()
        phase_started = perf_counter()
        self._index_evidence()
        self.stats["index_seconds"] = round(perf_counter() - phase_started, 6)
        phase_started = perf_counter()
        self._audit_signatures()
        self.stats["signature_seconds"] = round(perf_counter() - phase_started, 6)
        phase_started = perf_counter()
        self._audit_graph()
        self._sanitize_results()
        self.stats["graph_seconds"] = round(perf_counter() - phase_started, 6)
        if build_edges:
            phase_started = perf_counter()
            self._build_edges()
            self.stats["edge_seconds"] = round(perf_counter() - phase_started, 6)
        phase_started = perf_counter()
        report = self.public_report()
        self.stats["report_seconds"] = round(perf_counter() - phase_started, 6)
        self._audited = True
        return report

    def audit_approval(
        self, approval_id: str, *, build_edges: bool = False
    ) -> dict[str, Any]:
        """Audit the complete memoized graph and return one approval result."""
        if not self._audited:
            self.audit(build_edges=build_edges)
        return self.results[approval_id]

    def _index_evidence(self) -> None:
        for collection_name in ("revocations", "quarantines", "clearances"):
            items = self._visible_collection_uncached(collection_name)
            self.visible_records[collection_name] = items
            for notice in items:
                kind = normalize_target_type(
                    _first_present(
                        notice,
                        "target_type",
                        "target_kind",
                        "kind_target",
                        "kind",
                        "subject_type",
                    )
                )
                target_value = _first_present(
                    notice,
                    "target_id",
                    "target",
                    "id_target",
                    "subject_id",
                    "ref_id",
                )
                target_id: str
                if isinstance(target_value, dict):
                    kind = normalize_target_type(
                        kind or target_value.get("type") or target_value.get("kind")
                    )
                    target_id = str(
                        target_value.get("id")
                        or target_value.get("target_id")
                        or target_value.get("ref")
                        or ""
                    )
                else:
                    target_id = str(target_value or "")
                if kind not in {"approval", "signature", "key", "issuer"}:
                    # Schema-light bundles may omit target_type; an id match is
                    # then treated as a wildcard rather than silently dropped.
                    kind = "*"
                if target_id:
                    self.notice_index[(kind, target_id)].append(notice)

        checkpoints = self._visible_collection_uncached("checkpoints")
        self.visible_records["checkpoints"] = checkpoints
        for checkpoint in checkpoints:
            approval_id = str(
                checkpoint.get("approval_id")
                or checkpoint.get("approval")
                or checkpoint.get("target_id")
                or ""
            )
            if approval_id:
                self.checkpoints_by_approval[approval_id].append(checkpoint)

    # ---------- time / notices ----------

    def approval_time(self, approval_id: str) -> datetime:
        return self._approval_time_pair(approval_id)[0]

    def approval_time_text(self, approval_id: str) -> str:
        return self._approval_time_pair(approval_id)[1]

    def _approval_time_pair(self, approval_id: str) -> tuple[datetime, str]:
        cached = self._approval_time_cache.get(approval_id)
        if cached is not None:
            return cached
        approval = self.approvals_by_id[approval_id]
        raw = approval.get("issued_at") or approval.get("signed_at")
        moment = parse_time(raw, f"approvals.{approval_id}.issued_at") if raw else self.issued_at_dt
        text = moment.isoformat().replace("+00:00", "Z")
        pair = (moment, text)
        self._approval_time_cache[approval_id] = pair
        return pair

    def _key_interval(
        self, key: dict[str, Any]
    ) -> tuple[datetime | None, datetime | None]:
        key_id = str(key.get("key_id") or "")
        cached = self._key_interval_cache.get(key_id)
        if cached is not None:
            return cached
        start_raw = _first_present(key, "valid_from", "not_before")
        end_raw = _first_present(key, "valid_to", "expires_at", "not_after")
        start = parse_time(start_raw, "key.valid_from") if start_raw else None
        end = parse_time(end_raw, "key.valid_to") if end_raw else None
        interval = (start, end)
        self._key_interval_cache[key_id] = interval
        return interval

    def _visible_collection_uncached(self, name: str) -> list[dict[str, Any]]:
        return [
            item
            for item in self.bundle.get(name, [])
            if isinstance(item, dict) and visible_at(item, self.known_at_dt)
        ]

    def _visible_collection(self, name: str) -> list[dict[str, Any]]:
        if name in self.visible_records:
            return self.visible_records[name]
        return self._visible_collection_uncached(name)

    def _target_notices(
        self, collection: list[dict[str, Any]], target_type: str, target_id: str
    ) -> list[dict[str, Any]]:
        # ``collection`` is retained for call-site readability; the shared
        # target index avoids scanning every notice for every approval.
        exact = self.notice_index.get((target_type, target_id), ())
        wildcard = self.notice_index.get(("*", target_id), ())
        if not wildcard:
            return exact
        return [*exact, *wildcard]

    def _effective_time(self, notice: dict[str, Any], *, field: str = "effective_at") -> datetime:
        raw = _first_present(
            notice,
            field,
            "retroactive_to",
            "retroactive_at",
            "revoked_at" if field == "effective_at" else "at",
            "at",
        )
        if raw is None:
            raw = notice.get("published_at")
        if raw is None:
            return self.known_at_dt
        return parse_time(raw, f"{notice.get('id', 'notice')}.effective_at")

    # ---------- HMAC / key evidence ----------

    def _audit_signatures(self) -> None:
        revocations = self._visible_collection("revocations")
        quarantines = self._visible_collection("quarantines")
        clearances = self._visible_collection("clearances")

        for signature in self.bundle.get("signatures", []):
            if not isinstance(signature, dict):
                continue
            signature_id = str(signature.get("id") or signature.get("signature_id") or "")
            if not signature_id:
                raise BundleError("every signature needs an id")
            if not visible_at(signature, self.known_at_dt):
                continue

            approval_id = str(
                _first_present(signature, "approval_id", "approval", "target_id") or ""
            )
            approval = self.approvals_by_id.get(approval_id)
            report: dict[str, Any] = {
                "signature_id": signature_id,
                "approval_id": approval_id,
                "issuer_id": signature.get("issuer_id")
                or signature.get("issuer")
                or signature.get("signer_id")
                or signature.get("signer"),
                "key_id": signature.get("key_id") or signature.get("key"),
                "status": "not_evaluated",
                "usable": False,
                "hmac_valid": None,
                "time_valid": None,
                "reasons": [],
                "evidence_ids": {
                    "revocations": [],
                    "quarantines": [],
                    "clearances": [],
                },
                "first_failure_at": None,
            }
            self.stats["signature_reports"] += 1

            if approval is None:
                report["status"] = "orphan_signature"
                report["reasons"].append("approval_not_in_bundle")
                self.signature_reports[signature_id] = report
                continue

            issuer_id = str(report["issuer_id"] or "")
            key_id = str(report["key_id"] or "")
            key = self.keys_by_id.get(key_id)
            signed_at = (
                parse_time(signature["signed_at"], "signature.signed_at")
                if signature.get("signed_at")
                else (
                    parse_time(signature["issued_at"], "signature.issued_at")
                    if signature.get("issued_at")
                    else self.approval_time(approval_id)
                )
            )

            if key is None:
                report["status"] = "unknown_key"
                report["reasons"].append("key_not_present")
                report["first_failure_at"] = self.known_at
            else:
                key_issuer = str(key.get("issuer_id") or key.get("issuer") or "")
                if issuer_id and key_issuer and key_issuer != issuer_id:
                    report["reasons"].append("issuer_key_mismatch")

                approval_time_text = self.approval_time_text(approval_id)
                supplied = str(
                    _first_present(signature, "hmac", "signature", "value", "mac") or ""
                )
                report["hmac_valid"] = verify_signature(
                    approval, approval_time_text, key, supplied
                )
                if report["hmac_valid"] is False:
                    report["reasons"].append("hmac_mismatch")

                valid_from, valid_to = self._key_interval(key)
                report["time_valid"] = within_interval(
                    signed_at,
                    valid_from,
                    valid_to,
                    start_field="key.valid_from",
                    end_field="key.valid_to",
                    end_inclusive=True,
                )
                if report["time_valid"] is False:
                    report["reasons"].append("key_outside_validity")

            applicable_revocations: list[dict[str, Any]] = []
            for target_type, target_id in (
                ("signature", signature_id),
                ("key", key_id),
                ("issuer", issuer_id),
            ):
                for revocation in self._target_notices(
                    revocations, target_type, target_id
                ):
                    effective = self._effective_time(revocation)
                    if effective <= signed_at:
                        applicable_revocations.append(revocation)
                        report["evidence_ids"]["revocations"].append(
                            str(revocation.get("id", ""))
                        )
            if applicable_revocations:
                report["status"] = "revoked"
                report["reasons"].append("revocation_applicable")
                report["first_failure_at"] = min(
                    self._effective_time(r) for r in applicable_revocations
                ).isoformat().replace("+00:00", "Z")

            quarantined = False
            for target_type, target_id in (
                ("signature", signature_id),
                ("key", key_id),
                ("issuer", issuer_id),
            ):
                for quarantine in self._target_notices(
                    quarantines, target_type, target_id
                ):
                    start = _first_present(
                        quarantine, "start_at", "from", "valid_from", "quarantined_at"
                    )
                    end = _first_present(quarantine, "end_at", "to", "until", "valid_to")
                    if not within_interval(
                        signed_at,
                        start,
                        end,
                        start_field="quarantine.start_at",
                        end_field="quarantine.end_at",
                    ):
                        continue
                    qid = str(quarantine.get("id", ""))
                    report["evidence_ids"]["quarantines"].append(qid)
                    embedded_clear = quarantine.get("resolution") == "cleared" or quarantine.get(
                        "cleared"
                    ) is True
                    clearing_notices = [
                        c
                        for c in clearances
                        if str(c.get("quarantine_id", "")) == qid
                        or (
                            normalize_target_type(c.get("target_type")) == target_type
                            and str(c.get("target_id", "")) == target_id
                        )
                    ]
                    if embedded_clear or clearing_notices:
                        report["evidence_ids"]["clearances"].extend(
                            str(c.get("id", "")) for c in clearing_notices
                        )
                        report["reasons"].append("quarantine_cleared")
                    else:
                        quarantined = True
                        report["reasons"].append("quarantined_unresolved")

            if report["status"] != "revoked":
                if "issuer_key_mismatch" in report["reasons"]:
                    report["status"] = "issuer_mismatch"
                    report["first_failure_at"] = self.known_at
                elif report["hmac_valid"] is False:
                    report["status"] = "invalid_hmac"
                    report["first_failure_at"] = self.known_at
                elif report["time_valid"] is False:
                    report["status"] = "key_expired_or_not_valid"
                    report["first_failure_at"] = self.known_at
                elif key is not None and report["hmac_valid"] and report["time_valid"]:
                    if quarantined:
                        report["status"] = "quarantined"
                    else:
                        report["status"] = "valid"
                        report["usable"] = True
                elif quarantined:
                    report["status"] = "quarantined"

            if report["status"] == "valid" and "quarantined_unresolved" in report["reasons"]:
                report["status"] = "quarantined"
                report["usable"] = False

            self.signature_reports[signature_id] = report
            self.signatures_by_approval[approval_id].append(report)

        for reports in self.signatures_by_approval.values():
            reports.sort(key=lambda r: r["signature_id"])

    def _direct_proof(self, approval_id: str) -> dict[str, Any]:
        reports = self.signatures_by_approval.get(approval_id, [])
        representatives: dict[str, dict[str, Any]] = {}
        quarantined_issuers: dict[str, str] = {}
        for report in reports:
            issuer = str(report.get("issuer_id") or "")
            if report["usable"] and issuer:
                current = representatives.get(issuer)
                if current is None or report["signature_id"] < current["signature_id"]:
                    representatives[issuer] = report
            elif report["status"] == "quarantined" and issuer:
                quarantined_issuers.setdefault(issuer, report["signature_id"])

        chosen = sorted(representatives.values(), key=lambda r: r["signature_id"])[
            : self.threshold
        ]
        issuer_ids = sorted(str(r["issuer_id"]) for r in chosen)
        quorum_met = len({r["issuer_id"] for r in chosen}) >= self.threshold
        can_reach_with_quarantine = (
            len(representatives) + len(set(quarantined_issuers) - set(representatives))
            >= self.threshold
        )
        return {
            "quorum_met": quorum_met,
            "chosen_reports": chosen,
            "trusted_issuer_count": len(representatives),
            "trusted_issuer_ids": sorted(representatives),
            "quarantined_issuer_ids": sorted(quarantined_issuers),
            "could_reach_threshold_after_clearance": can_reach_with_quarantine,
            "same_issuer_key_rotation_collapsed": any(
                sum(1 for r in reports if r.get("issuer_id") == issuer) > 1
                for issuer in representatives
            ),
        }

    # ---------- checkpoints ----------

    def _checkpoint_for(self, approval_id: str) -> dict[str, Any] | None:
        checkpoints = self.checkpoints_by_approval.get(approval_id, [])
        valid: list[tuple[datetime, str, dict[str, Any]]] = []
        for checkpoint in checkpoints:
            cid = str(checkpoint.get("id") or "checkpoint")
            expected = checkpoint.get("digest")
            digest_ok = None
            if expected and self.verify_digests:
                expected_text = str(expected).removeprefix("sha256:")
                digest_ok = checkpoint_digest(checkpoint) == expected_text
            report = {
                "checkpoint_id": cid,
                "approval_id": approval_id,
                "decision": checkpoint.get("decision", "trusted"),
                "digest_verified": digest_ok,
                "used": False,
                "reason": None,
            }
            if digest_ok is False:
                report["reason"] = "digest_mismatch"
                self.checkpoint_reports.append(report)
                continue
            when_raw = _first_present(checkpoint, "frozen_at", "at", "published_at")
            when = parse_time(when_raw, "checkpoint.at") if when_raw else self.known_at_dt
            valid.append((when, cid, checkpoint))
            self.checkpoint_reports.append(report)
        if not valid:
            return None
        valid.sort(key=lambda item: (item[0], item[1]))
        return valid[-1][2]

    def _checkpoint_conflict(self, checkpoint: dict[str, Any]) -> str | None:
        """Return a reason if new adverse evidence contradicts a frozen witness."""
        witness = checkpoint.get("witness")
        covered = set(checkpoint.get("covered_signature_ids", []) or [])
        if isinstance(witness, dict):
            covered.update(witness.get("signature_ids", []) or [])
        hard_bad = {
            "revoked",
            "invalid_hmac",
            "issuer_mismatch",
            "unknown_key",
            "key_expired_or_not_valid",
        }
        for signature_id in covered:
            report = self.signature_reports.get(str(signature_id))
            if not report:
                continue
            if report.get("status") in hard_bad:
                return "checkpoint_witness_revoked_or_invalid"
            if report.get("status") == "quarantined":
                return "checkpoint_witness_quarantined"
        return None

    # ---------- approval graph ----------

    def _audit_graph(self) -> None:
        node_ids = sorted(self.approvals_by_id)
        components = strongly_connected_components(node_ids, self.requires, self.dependents)
        scc_id, order = topological_scc_order(components, self.requires)
        self.components = components
        self.scc_id = scc_id
        self.scc_order = order
        self.stats["scc_count"] = len(components)
        self.cycles = build_cycle_evidence(components, self.requires)
        self.stats["cycle_count"] = len(self.cycles)
        cycle_lookup = {cycle["cycle_id"]: cycle for cycle in self.cycles}
        for index, component in enumerate(components):
            members = set(component)
            internal_edges = [
                (u, v)
                for u in component
                for v in self.requires.get(u, [])
                if v in members
            ]
            is_cyclic = len(component) > 1 or internal_edges
            if is_cyclic:
                path = None
                for cycle in self.cycles:
                    if set(cycle["nodes"]) == members or all(
                        n in members for n in cycle["representative_path"]
                    ):
                        self.cycle_by_scc[index] = cycle["cycle_id"]
                        break

        for component_index in order:
            component = components[component_index]
            cyclic = component_index in self.cycle_by_scc
            bases = {
                node: self._base_result(node, component_index, set(component))
                for node in component
            }
            self.results.update(bases)

            if not cyclic:
                node = component[0]
                self._finalize_singleton(node)
                self.stats["approvals_evaluated"] += 1
                continue

            self._resolve_cyclic_component(component, bases)
            self.stats["approvals_evaluated"] += len(component)

    def _base_result(
        self, node: str, scc_index: int, scc_members: set[str]
    ) -> dict[str, Any]:
        approval = self.approvals_by_id[node]
        proof = self._direct_proof(node)
        approval_dt = self.approval_time(node)
        revocations = self._visible_collection("revocations")
        quarantines = self._visible_collection("quarantines")

        approval_revocations = [
            r
            for r in self._target_notices(revocations, "approval", node)
            if self._effective_time(r) <= approval_dt
        ]
        approval_quarantines = [
            q
            for q in self._target_notices(quarantines, "approval", node)
            if within_interval(
                approval_dt,
                _first_present(q, "start_at", "from"),
                _first_present(q, "end_at", "to", "until"),
            )
            and not (q.get("resolution") == "cleared" or q.get("cleared") is True)
        ]
        checkpoint = self._checkpoint_for(node)
        checkpoint_decision = str(checkpoint.get("decision", "trusted")) if checkpoint else None
        all_refs = list(self.requires.get(node, ()))

        external_deps = [dep for dep in all_refs if dep not in scc_members]
        dep_results = [self.results[dep] for dep in external_deps if dep in self.results]

        result: dict[str, Any] = {
            "approval_id": node,
            "decision": "inconclusive",
            "classification": "insufficient_evidence",
            "certainty": "uncertain",
            "reason_code": "not_resolved",
            "reason_codes": [],
            "threshold": self.threshold,
            "independent_issuer_count": proof["trusted_issuer_count"],
            "minimal_witness": None,
            "witness": None,
            "cycle_id": self.cycle_by_scc.get(scc_index),
            "checkpoint_id": checkpoint.get("id") if checkpoint else None,
            "rejection": None,
            "uncertainty": None,
            "signature_ids": [r["signature_id"] for r in self.signatures_by_approval.get(node, [])],
            "usable_signature_ids": [
                r["signature_id"]
                for r in proof["chosen_reports"]
            ],
            "prerequisite_ids": all_refs,
            "evidence_ids": {
                "approval_revocations": [r.get("id") for r in approval_revocations],
                "approval_quarantines": [q.get("id") for q in approval_quarantines],
            },
            "_proof": proof,
            "_checkpoint": checkpoint,
            "_scc_index": scc_index,
            "_internal_requires": [dep for dep in all_refs if dep in scc_members],
            "_local_trust_possible": False,
            "_blocker": None,
        }

        if approval.get("_missing"):
            result["reason_code"] = "missing_referenced_approval"
            result["reason_codes"].append("missing_referenced_approval")
            result["classification"] = "insufficient_evidence"
            return result

        if approval_revocations:
            rev = sorted(approval_revocations, key=lambda r: str(r.get("id", "")))[0]
            result["decision"] = "rejected"
            result["classification"] = "definite_rejection"
            result["certainty"] = "definite"
            result["reason_code"] = "approval_revoked"
            result["reason_codes"].append("approval_revoked")
            result["rejection"] = {
                "code": "approval_revoked",
                "evidence_id": rev.get("id"),
                "effective_at": self._effective_time(rev)
                .isoformat()
                .replace("+00:00", "Z"),
            }
            return result

        if checkpoint and checkpoint_decision == "rejected":
            self.stats["checkpoints_rejected"] += 1
            result["decision"] = "rejected"
            result["classification"] = "definite_rejection"
            result["certainty"] = "definite"
            result["reason_code"] = "frozen_checkpoint_rejected"
            result["reason_codes"].append("frozen_checkpoint_rejected")
            result["rejection"] = {
                "code": "frozen_checkpoint_rejected",
                "evidence_id": checkpoint.get("id"),
            }
            for report in self.checkpoint_reports:
                if report["checkpoint_id"] == checkpoint.get("id"):
                    report["used"] = True
            return result

        rejected_dep = next((r for r in dep_results if r["decision"] == "rejected"), None)
        if rejected_dep:
            result["decision"] = "rejected"
            result["classification"] = "definite_rejection"
            result["certainty"] = "definite"
            result["reason_code"] = "dependency_rejected"
            result["reason_codes"].append("dependency_rejected")
            result["rejection"] = {
                "code": "dependency_rejected",
                "approval_id": rejected_dep["approval_id"],
                "downstream_edge_id": f"reference:{node}->{rejected_dep['approval_id']}",
                "source_rejection": rejected_dep.get("rejection"),
            }
            return result

        if approval_quarantines:
            result["reason_code"] = "approval_quarantined"
            result["reason_codes"].append("approval_quarantined")
            result["uncertainty"] = {
                "code": "quarantined",
                "evidence_ids": [q.get("id") for q in approval_quarantines],
            }
            result["_blocker"] = "quarantined"
            return result

        quarantined_dep = next(
            (
                r
                for r in dep_results
                if r["decision"] == "quarantined"
                or "quarantine" in str(r.get("reason_code", ""))
            ),
            None,
        )
        if quarantined_dep:
            qdep = quarantined_dep
            result["decision"] = "quarantined"
            result["classification"] = "insufficient_evidence"
            result["certainty"] = "uncertain"
            result["reason_code"] = "dependency_quarantined"
            result["uncertainty"] = {
                "code": "dependency_quarantined",
                "approval_id": qdep["approval_id"],
            }
            result["_blocker"] = "quarantined"
            return result

        unproven_dep = next((r for r in dep_results if r["decision"] != "trusted"), None)
        cp_trusted = bool(checkpoint and checkpoint_decision == "trusted")
        cp_conflict = self._checkpoint_conflict(checkpoint) if cp_trusted else None
        if cp_conflict:
            cp_trusted = False
            result["stale_checkpoint_id"] = checkpoint.get("id")
            result["reason_codes"].append(cp_conflict)
            for report in self.checkpoint_reports:
                if report["checkpoint_id"] == checkpoint.get("id"):
                    report["used"] = False
                    report["reason"] = cp_conflict
        elif cp_trusted:
            result["checkpoint_id"] = checkpoint.get("id")
            result["_local_trust_possible"] = True
            result["_checkpoint_trusted"] = True
            self.stats["checkpoint_hits"] += 1
            for report in self.checkpoint_reports:
                if report["checkpoint_id"] == checkpoint.get("id"):
                    report["used"] = True
        elif proof["quorum_met"]:
            result["_local_trust_possible"] = True

        if unproven_dep and not cp_trusted:
            result["reason_code"] = "dependency_unproven"
            result["reason_codes"].append("dependency_unproven")
            result["_blocker"] = "dependency_unproven"
            result["uncertainty"] = {
                "code": "dependency_unproven",
                "approval_id": unproven_dep["approval_id"],
                "dependency_reason": unproven_dep.get("reason_code"),
            }
            return result

        if not proof["quorum_met"] and not cp_trusted:
            if proof["quarantined_issuer_ids"]:
                result["decision"] = "quarantined"
                result["reason_code"] = "quarantined_witness"
                result["uncertainty"] = {
                    "code": "quarantined_witness",
                    "issuer_ids": proof["quarantined_issuer_ids"],
                    "could_reach_threshold_after_clearance": proof[
                        "could_reach_threshold_after_clearance"
                    ],
                }
                result["_blocker"] = "quarantined"
            else:
                result["reason_code"] = "below_threshold"
                result["uncertainty"] = {
                    "code": "insufficient_independent_issuers",
                    "have": proof["trusted_issuer_count"],
                    "threshold": self.threshold,
                }
                result["_blocker"] = "no_quorum"
            result["reason_codes"].append(result["reason_code"])
            return result

        # Local evidence is sufficient; internal cycle dependencies may still
        # prevent final trust in the SCC fixed-point pass.
        if not result["_internal_requires"]:
            self._mark_trusted(result, checkpoint_used=cp_trusted)
        return result

    def _finalize_singleton(self, node: str) -> None:
        result = self.results[node]
        if result["decision"] == "rejected":
            return
        if result.get("_blocker") == "quarantined":
            result["decision"] = "quarantined"
            return
        if result.get("_blocker"):
            return
        if result.get("_local_trust_possible") and not result["_internal_requires"]:
            self._mark_trusted(result, bool(result.get("_checkpoint_trusted")))
        elif result["cycle_id"]:
            result["reason_code"] = "unresolved_reference_cycle"
            result["classification"] = "insufficient_evidence"

    def _resolve_cyclic_component(
        self, component: list[str], bases: dict[str, dict[str, Any]]
    ) -> None:
        members = set(component)
        reverse_internal: dict[str, list[str]] = {node: [] for node in component}
        for node in component:
            for prereq in bases[node]["_internal_requires"]:
                if prereq in members:
                    reverse_internal[prereq].append(node)
        for values in reverse_internal.values():
            values.sort()

        rejected_queue = deque(
            node for node in component if bases[node]["decision"] == "rejected"
        )
        while rejected_queue:
            current = rejected_queue.popleft()
            for dependent in reverse_internal[current]:
                target = bases[dependent]
                if target["decision"] != "rejected":
                    target["decision"] = "rejected"
                    target["classification"] = "definite_rejection"
                    target["certainty"] = "definite"
                    target["reason_code"] = "dependency_rejected"
                    target["reason_codes"].append("dependency_rejected")
                    target["rejection"] = {
                        "code": "dependency_rejected",
                        "approval_id": current,
                        "downstream_edge_id": f"reference:{dependent}->{current}",
                        "source_rejection": target.get("rejection"),
                    }
                    target["_blocker"] = "rejected"
                    rejected_queue.append(dependent)
                    self.stats["internal_propagations"] += 1

        quarantine_queue = deque(
            node
            for node in component
            if bases[node].get("_blocker") == "quarantined"
            and bases[node]["decision"] != "rejected"
        )
        quarantined_seen = set(quarantine_queue)
        while quarantine_queue:
            current = quarantine_queue.popleft()
            for dependent in reverse_internal[current]:
                target = bases[dependent]
                if target["decision"] == "rejected" or dependent in quarantined_seen:
                    continue
                target["decision"] = "quarantined"
                target["classification"] = "insufficient_evidence"
                target["certainty"] = "uncertain"
                target["reason_code"] = "dependency_quarantined"
                target["_blocker"] = "quarantined"
                target["uncertainty"] = {
                    "code": "dependency_quarantined",
                    "approval_id": current,
                }
                quarantined_seen.add(dependent)
                quarantine_queue.append(dependent)
                self.stats["internal_propagations"] += 1

        trusted_queue: deque[str] = deque()
        for node in component:
            result = bases[node]
            if result["decision"] == "rejected" or result.get("_blocker") == "quarantined":
                continue
            if result.get("_checkpoint_trusted"):
                # A frozen checkpoint is an anchor unless rejection/quarantine
                # propagation above has already invalidated it.
                self._mark_trusted(result, checkpoint_used=True)
                trusted_queue.append(node)
            elif result.get("_local_trust_possible") and not result["_internal_requires"]:
                self._mark_trusted(result)
                trusted_queue.append(node)

        while trusted_queue:
            current = trusted_queue.popleft()
            for dependent in reverse_internal[current]:
                target = bases[dependent]
                if target["decision"] in {"trusted", "rejected", "quarantined"}:
                    continue
                if not target.get("_local_trust_possible"):
                    continue
                internal = target["_internal_requires"]
                if all(bases[dep]["decision"] == "trusted" for dep in internal):
                    self._mark_trusted(
                        target, checkpoint_used=bool(target.get("_checkpoint_trusted"))
                    )
                    trusted_queue.append(dependent)
                    self.stats["internal_propagations"] += 1

        for node in component:
            result = bases[node]
            if result["decision"] == "trusted" or result["decision"] == "rejected":
                continue
            if result.get("_blocker") == "quarantined" or result["decision"] == "quarantined":
                result["decision"] = "quarantined"
                result["classification"] = "insufficient_evidence"
                continue
            if result.get("_local_trust_possible"):
                result["decision"] = "inconclusive"
                result["classification"] = "insufficient_evidence"
                result["reason_code"] = "unresolved_reference_cycle"
                if "unresolved_reference_cycle" not in result["reason_codes"]:
                    result["reason_codes"].append("unresolved_reference_cycle")
                result["uncertainty"] = {
                    "code": "reference_cycle_without_frozen_anchor",
                    "cycle_id": result["cycle_id"],
                }
            elif result["reason_code"] == "not_resolved":
                result["reason_code"] = "unresolved_reference_cycle"

    def _mark_trusted(self, result: dict[str, Any], checkpoint_used: bool = False) -> None:
        if result["decision"] == "trusted":
            return
        proof = result["_proof"]
        chosen = proof["chosen_reports"]
        witness = {
            "minimal": True,
            "threshold": self.threshold,
            "signature_ids": [r["signature_id"] for r in chosen],
            "issuer_ids": sorted({str(r["issuer_id"]) for r in chosen}),
            "independent_issuer_count": len({str(r["issuer_id"]) for r in chosen}),
            "prerequisite_ids": list(result["prerequisite_ids"]),
            "prerequisite_proof_refs": [
                f"proof:{dep}"
                for dep in result["prerequisite_ids"]
                if self.results.get(dep, {}).get("decision") == "trusted"
            ],
            "proof_ref": f"proof:{result['approval_id']}",
            "checkpoint_id": result.get("checkpoint_id") if checkpoint_used else None,
        }
        if checkpoint_used and result.get("_checkpoint") and not chosen:
            checkpoint = result["_checkpoint"]
            frozen_witness = checkpoint.get("witness")
            if isinstance(frozen_witness, dict):
                witness["frozen_witness"] = frozen_witness
            witness["independent_issuer_count"] = frozen_witness.get(
                "independent_issuer_count", self.threshold
            ) if isinstance(frozen_witness, dict) else self.threshold
        result["decision"] = "trusted"
        result["classification"] = "trusted"
        result["certainty"] = "proven"
        result["reason_code"] = "threshold_witness"
        result["minimal_witness"] = witness
        result["witness"] = witness
        result["uncertainty"] = None
        self.stats["proof_nodes_built"] += 1

    def _sanitize_results(self) -> None:
        for result in self.results.values():
            for key in [k for k in result if k.startswith("_")]:
                del result[key]
            decision = result["decision"]
            coarse_status = "uncertain" if decision in {"inconclusive", "quarantined"} else decision
            result["status"] = coarse_status
            result["verdict"] = coarse_status
            result["is_trusted"] = decision == "trusted"
            result["is_rejected"] = decision == "rejected"
            result["is_uncertain"] = coarse_status == "uncertain"

    # ---------- edges / report ----------

    def _rejection_evidence_ids(self, rejection: Any) -> list[str]:
        ids: set[str] = set()
        current = rejection
        seen = 0
        while isinstance(current, dict) and seen < 1000:
            evidence_id = current.get("evidence_id")
            if evidence_id:
                ids.add(str(evidence_id))
            current = current.get("source_rejection")
            seen += 1
        return sorted(ids)

    def _build_edges(self) -> None:
        for signature_id, report in sorted(self.signature_reports.items()):
            status = report["status"]
            if status in {"valid"}:
                edge_status = "valid"
            elif status in {"quarantined"}:
                edge_status = "uncertain"
            else:
                edge_status = "failed"
            self.edge_results[f"signature:{signature_id}"] = {
                "edge_id": f"signature:{signature_id}",
                "kind": "signature",
                "status": edge_status,
                "detail_status": status,
                "approval_id": report["approval_id"],
                "signature_id": signature_id,
                "issuer_id": report.get("issuer_id"),
                "key_id": report.get("key_id"),
                "evidence_ids": report.get("evidence_ids", {}),
                "first_failure_at": report.get("first_failure_at"),
            }

        for approval_id in sorted(self.approvals_by_id):
            result = self.results[approval_id]
            decision = result["decision"]
            evidence = dict(result.get("evidence_ids", {}))
            evidence["rejection_chain"] = self._rejection_evidence_ids(
                result.get("rejection")
            )
            self.edge_results[f"validity:{approval_id}"] = {
                "edge_id": f"validity:{approval_id}",
                "kind": "approval_validity",
                "status": "valid" if decision == "trusted" else (
                    "failed" if decision == "rejected" else "uncertain"
                ),
                "detail_status": decision,
                "approval_id": approval_id,
                "evidence_ids": evidence,
                "first_failure_at": (
                    result.get("rejection", {}).get("effective_at")
                    if isinstance(result.get("rejection"), dict)
                    else None
                ),
            }

        for approval_id in sorted(self.requires):
            for prereq in self.requires[approval_id]:
                edge_id = f"reference:{approval_id}->{prereq}"
                prereq_result = self.results.get(prereq, {})
                decision = prereq_result.get("decision", "inconclusive")
                if decision == "trusted":
                    status = "supported"
                elif decision == "rejected":
                    status = "failed"
                elif decision == "quarantined":
                    status = "uncertain"
                else:
                    status = "incomplete"
                rejection = prereq_result.get("rejection")
                self.edge_results[edge_id] = {
                    "edge_id": edge_id,
                    "kind": "reference",
                    "status": status,
                    "detail_status": decision,
                    "approval_id": approval_id,
                    "prerequisite_id": prereq,
                    "evidence_ids": self._rejection_evidence_ids(rejection),
                    "first_failure_at": (
                        rejection.get("effective_at")
                        if isinstance(rejection, dict) and rejection.get("effective_at")
                        else None
                    ),
                }

    def public_report(self, *, include_signatures: bool = True) -> dict[str, Any]:
        real_ids = sorted(approval["id"] for approval in self.bundle["approvals"])
        approvals = [self.results[approval_id] for approval_id in real_ids]

        counts = {"trusted": 0, "rejected": 0, "inconclusive": 0, "quarantined": 0}
        for result in approvals:
            if result["decision"] == "trusted":
                counts["trusted"] += 1
            elif result["decision"] == "rejected":
                counts["rejected"] += 1
            elif result["decision"] == "quarantined":
                counts["quarantined"] += 1
            else:
                counts["inconclusive"] += 1

        report = {
            "schema_version": "keychronicle.audit/1",
            "issued_at": self.issued_at,
            "known_at": self.known_at,
            "threshold": self.threshold,
            "terminal_ids": self.terminal_ids,
            "summary": {
                "total_approvals": len(self.bundle["approvals"]),
                **counts,
                "cycles": len(self.cycles),
                "checkpoint_hits": self.stats["checkpoint_hits"],
            },
            "stats": self.stats,
            "approvals": approvals,
            "cycles": self.cycles,
        }
        if include_signatures:
            report["signature_reports"] = sorted(
                self.signature_reports.values(),
                key=lambda item: item["signature_id"],
            )
            report["checkpoint_reports"] = self.checkpoint_reports
        return report


def audit_bundle(
    bundle: dict[str, Any],
    issued_at: str | datetime,
    known_at: str | datetime,
    *,
    threshold: int | None = None,
    build_edges: bool = False,
) -> dict[str, Any]:
    engine = AuditEngine(bundle, issued_at, known_at, threshold=threshold)
    return engine.audit(build_edges=build_edges)
