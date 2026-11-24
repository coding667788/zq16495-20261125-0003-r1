from __future__ import annotations

from collections import deque
from typing import Any

from .engine import AuditEngine


def bfs_stable_paths(
    source: str, adjacency: dict[str, list[str]]
) -> tuple[dict[str, int], dict[str, str]]:
    """BFS using sorted adjacency; first visit is the stable shortest tie."""
    distances = {source: 0}
    predecessors: dict[str, str] = {}
    queue: deque[str] = deque([source])
    while queue:
        node = queue.popleft()
        for neighbor in adjacency.get(node, []):
            if neighbor not in distances:
                distances[neighbor] = distances[node] + 1
                predecessors[neighbor] = node
                queue.append(neighbor)
    return distances, predecessors


def reconstruct_path(target: str, predecessors: dict[str, str]) -> list[str]:
    path = [target]
    while path[-1] in predecessors:
        path.append(predecessors[path[-1]])
    path.reverse()
    return path


def terminal_reachability(engine: AuditEngine, terminal_ids: list[str]) -> dict[str, list[str]]:
    """Memoized SCC reachability: node -> all terminals downstream of it.

    A shared prerequisite/SCC is unioned once rather than re-walked for every
    parent.  Returned lists are stable and shared per SCC.
    """
    terminal_set = set(terminal_ids)
    reach_sets: dict[int, set[str]] = {}
    reach_lists: dict[int, list[str]] = {}

    # engine.scc_order is prerequisite-first; reversed visits consumers first.
    for scc_index in reversed(engine.scc_order):
        members = engine.components[scc_index]
        reach: set[str] = {node for node in members if node in terminal_set}
        for node in members:
            for dependent in engine.dependents.get(node, []):
                dependent_scc = engine.scc_id.get(dependent)
                if dependent_scc is None or dependent_scc == scc_index:
                    continue
                reach.update(reach_sets.get(dependent_scc, set()))
        reach_sets[scc_index] = reach
        reach_lists[scc_index] = sorted(reach)

    return {
        node: reach_lists[engine.scc_id[node]]
        for node in engine.scc_id
        if node in engine.scc_id
    }


def _flatten_evidence(edge: dict[str, Any], late_engine: AuditEngine) -> list[str]:
    ids: list[str] = []
    evidence = edge.get("evidence_ids", {})
    if isinstance(evidence, dict):
        for value in evidence.values():
            if isinstance(value, list):
                ids.extend(str(v) for v in value if v)
    elif isinstance(evidence, list):
        ids.extend(str(v) for v in evidence if v)
    if edge.get("signature_id"):
        report = late_engine.signature_reports.get(edge["signature_id"], {})
        rev_ids = report.get("evidence_ids", {}).get("revocations", [])
        ids.extend(str(v) for v in rev_ids if v)
    return sorted(set(ids))


def _evidence_details(
    evidence_ids: list[str], late_engine: AuditEngine
) -> list[dict[str, Any]]:
    wanted = set(evidence_ids)
    details = []
    for collection_name in ("revocations", "quarantines", "clearances", "checkpoints"):
        for item in late_engine.bundle.get(collection_name, []):
            if str(item.get("id", "")) not in wanted:
                continue
            details.append(
                {
                    "id": item.get("id"),
                    "kind": collection_name.rstrip("s"),
                    "target_type": item.get("target_type"),
                    "target_id": item.get("target_id"),
                    "published_at": item.get("published_at"),
                    "effective_at": item.get("effective_at")
                    or item.get("retroactive_to")
                    or item.get("at"),
                }
            )
    details.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    return details


def diff_knowledge_cuts(
    bundle: dict[str, Any],
    issued_at: str,
    from_known_at: str,
    to_known_at: str,
    *,
    threshold: int | None = None,
) -> dict[str, Any]:
    early = AuditEngine(bundle, issued_at, from_known_at, threshold=threshold)
    late = AuditEngine(bundle, issued_at, to_known_at, threshold=threshold)
    return diff_engines(early, late)


def diff_bundle_snapshots(
    early_bundle: dict[str, Any],
    late_bundle: dict[str, Any],
    issued_at: str,
    *,
    from_known_at: str | None = None,
    to_known_at: str | None = None,
    threshold: int | None = None,
) -> dict[str, Any]:
    """Diff two separately serialized knowledge snapshots.

    A snapshot file is treated as containing exactly the evidence visible in
    that section; absent an explicit cutoff or embedded ``known_at``, all of
    its records are visible.
    """
    full_visibility = "9999-12-31T23:59:59Z"
    early_k = from_known_at or early_bundle.get("known_at") or full_visibility
    late_k = to_known_at or late_bundle.get("known_at") or full_visibility
    early = AuditEngine(early_bundle, issued_at, early_k, threshold=threshold)
    late = AuditEngine(late_bundle, issued_at, late_k, threshold=threshold)
    return diff_engines(early, late)


def diff_engines(early: AuditEngine, late: AuditEngine) -> dict[str, Any]:
    early_report = early.audit(build_edges=True)
    late_report = late.audit(build_edges=True)

    real_ids = {approval["id"] for approval in late.bundle["approvals"]}
    terminal_ids = [t for t in late.terminal_ids if t in real_ids]
    reachable_terminals = terminal_reachability(late, terminal_ids)
    early_results = {a["approval_id"]: a for a in early_report["approvals"]}
    late_results = {a["approval_id"]: a for a in late_report["approvals"]}

    all_edge_ids = sorted(set(early.edge_results) | set(late.edge_results))
    transitions: list[dict[str, Any]] = []
    first_failures: list[dict[str, Any]] = []
    direct_failures: list[dict[str, Any]] = []

    for edge_id in all_edge_ids:
        before_edge = early.edge_results.get(edge_id, {})
        after_edge = late.edge_results.get(edge_id, {})
        before_status = before_edge.get("status", "absent")
        after_status = after_edge.get("status", "absent")
        if before_status == after_status:
            continue
        transition = {
            "edge_id": edge_id,
            "kind": after_edge.get("kind") or before_edge.get("kind"),
            "before_status": before_status,
            "after_status": after_status,
            "first_failure_at": after_edge.get("first_failure_at"),
            "approval_id": after_edge.get("approval_id", before_edge.get("approval_id")),
            "prerequisite_id": after_edge.get(
                "prerequisite_id", before_edge.get("prerequisite_id")
            ),
            "signature_id": after_edge.get("signature_id"),
        }
        transitions.append(transition)

        if after_status != "failed" or before_status == "failed":
            continue

        kind = transition["kind"]
        approval_id = transition.get("approval_id")
        late_result = late_results.get(approval_id, {})
        rejection_code = (late_result.get("rejection") or {}).get("code")
        direct = kind == "signature" or (
            kind == "approval_validity"
            and rejection_code in {"approval_revoked", "frozen_checkpoint_rejected"}
        )

        # For u -> v, u is the entry point to the downstream graph for this
        # particular edge.  For validity/signature edges the approval itself is.
        entry_node = approval_id
        causal_source = approval_id
        if kind == "reference":
            causal_source = transition.get("prerequisite_id")

        affected_ids = reachable_terminals.get(entry_node, []) if entry_node else []
        failure_record: dict[str, Any] = {
            **transition,
            "causal_class": "direct_evidence" if direct else "propagated_reference",
            "entry_approval_id": entry_node,
            "causal_source_approval_id": causal_source,
            "evidence_ids": _flatten_evidence(after_edge, late),
            "affected_terminal_ids": affected_ids,
        }
        failure_record["evidence_details"] = _evidence_details(
            failure_record["evidence_ids"], late
        )

        if direct and causal_source and causal_source in late.approvals_by_id:
            distances, predecessors = bfs_stable_paths(causal_source, late.dependents)
            terminal_effects = []
            for terminal_id in terminal_ids:
                if terminal_id not in distances:
                    continue
                path = reconstruct_path(terminal_id, predecessors)
                before_decision = early_results.get(terminal_id, {}).get("decision", "absent")
                after_decision = late_results.get(terminal_id, {}).get("decision", "absent")
                terminal_effects.append(
                    {
                        "terminal_id": terminal_id,
                        "decision_before": before_decision,
                        "decision_after": after_decision,
                        "decision_changed": before_decision != after_decision,
                        "shortest_explanation": {
                            "hops": max(0, len(path) - 1),
                            "path_approvals": path,
                            "path_edges": [
                                f"reference:{path[i + 1]}->{path[i]}"
                                for i in range(len(path) - 1)
                            ],
                            "evidence_ids": failure_record["evidence_ids"],
                            "selection": "shortest_then_lexicographically_stable",
                        },
                    }
                )
            terminal_effects.sort(key=lambda item: item["terminal_id"])
            failure_record["terminal_effects"] = terminal_effects
            failure_record["changed_terminal_ids"] = sorted(
                item["terminal_id"]
                for item in terminal_effects
                if item["decision_changed"]
            )
            direct_failures.append(failure_record)

        first_failures.append(failure_record)

    uncertain_transitions = [
        {
            **transition,
            "entry_approval_id": transition.get("approval_id"),
            "affected_terminal_ids": reachable_terminals.get(
                transition.get("approval_id"), []
            ),
        }
        for transition in transitions
        if transition["after_status"] == "uncertain"
    ]

    terminal_changes = []
    all_changed_terminals = set()
    for terminal_id in terminal_ids:
        before_decision = early_results.get(terminal_id, {}).get("decision")
        after_decision = late_results.get(terminal_id, {}).get("decision")
        if before_decision == after_decision:
            continue
        all_changed_terminals.add(terminal_id)
        candidates = []
        for failure in direct_failures:
            for effect in failure.get("terminal_effects", []):
                if effect["terminal_id"] != terminal_id:
                    continue
                explanation = effect["shortest_explanation"]
                candidates.append(
                    {
                        "failure_edge_id": failure["edge_id"],
                        "hops": explanation["hops"],
                        "path_approvals": explanation["path_approvals"],
                        "path_edges": explanation["path_edges"],
                        "evidence_ids": sorted(
                            set(explanation["evidence_ids"])
                            | set(failure.get("evidence_ids", []))
                        ),
                    }
                )
        if candidates:
            best = min(
                candidates,
                key=lambda c: (
                    c["hops"],
                    tuple(c["path_approvals"]),
                    c["failure_edge_id"],
                    tuple(c["evidence_ids"]),
                ),
            )
            best["candidate_explanation_count"] = len(candidates)
            best["alternative_failure_source_count"] = max(0, len(candidates) - 1)
            # Backward-compatible descriptive alias used by early README text.
            best["alternative_explanation_count"] = len(candidates)
        else:
            best = {
                "hops": None,
                "path_approvals": [],
                "path_edges": [],
                "evidence_ids": [],
                "alternative_explanation_count": 0,
            }
        terminal_changes.append(
            {
                "terminal_id": terminal_id,
                "decision_before": before_decision,
                "decision_after": after_decision,
                "best_explanation": best,
            }
        )

    first_failures.sort(
        key=lambda f: (
            0 if f["causal_class"] == "direct_evidence" else 1,
            f.get("first_failure_at") or "",
            f["edge_id"],
        )
    )
    terminal_changes.sort(key=lambda c: c["terminal_id"])

    return {
        "schema_version": "keychronicle.diff/1",
        "issued_at": early.issued_at,
        "from_known_at": early.known_at,
        "to_known_at": late.known_at,
        "threshold": early.threshold,
        "terminal_ids": terminal_ids,
        "summary": {
            "changed_edge_count": len(transitions),
            "first_failed_edge_count": len(first_failures),
            "direct_failure_count": len(direct_failures),
            "new_uncertain_edge_count": len(uncertain_transitions),
            "changed_terminal_count": len(terminal_changes),
        },
        "first_failures": first_failures,
        "new_uncertainties": uncertain_transitions,
        "terminal_changes": terminal_changes,
        "affected_terminal_ids": sorted(all_changed_terminals),
        "edge_transitions": transitions,
        "cycles": late_report.get("cycles", []),
        "early_summary": early_report["summary"],
        "late_summary": late_report["summary"],
    }
