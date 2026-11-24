from __future__ import annotations

from collections import deque
from typing import Any

from .canonical import canonical_bytes, sha256_hex


def strongly_connected_components(
    node_ids: list[str],
    requires: dict[str, list[str]],
    dependents: dict[str, list[str]],
) -> list[list[str]]:
    """Iterative Kosaraju; returned components are sorted and stable."""
    ordered_ids = sorted(node_ids)
    visited: set[str] = set()
    finish_order: list[str] = []

    for start in ordered_ids:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, int]] = [(start, 0)]
        while stack:
            node, next_index = stack[-1]
            neighbors = requires.get(node, [])
            if next_index < len(neighbors):
                neighbor = neighbors[next_index]
                stack[-1] = (node, next_index + 1)
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append((neighbor, 0))
            else:
                finish_order.append(node)
                stack.pop()

    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        assigned.add(start)
        stack = [start]
        component: list[str] = []
        while stack:
            node = stack.pop()
            component.append(node)
            for neighbor in dependents.get(node, []):
                if neighbor not in assigned:
                    assigned.add(neighbor)
                    stack.append(neighbor)
        components.append(sorted(component))

    components.sort(key=lambda comp: (len(comp) != 1, comp[0], comp))
    return components


def topological_scc_order(
    components: list[list[str]],
    requires: dict[str, list[str]],
) -> tuple[dict[str, int], list[int]]:
    scc_id: dict[str, int] = {}
    for index, component in enumerate(components):
        for node in component:
            scc_id[node] = index

    producer_to_consumers: dict[int, set[int]] = {i: set() for i in range(len(components))}
    indegree: dict[int, int] = {i: 0 for i in range(len(components))}
    seen_edges: set[tuple[int, int]] = set()

    for node in sorted(scc_id):
        consumer = scc_id[node]
        for prereq in requires.get(node, []):
            producer = scc_id.get(prereq)
            if producer is None or producer == consumer:
                continue
            edge = (producer, consumer)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            if consumer not in producer_to_consumers[producer]:
                producer_to_consumers[producer].add(consumer)
                indegree[consumer] += 1

    ready = sorted(i for i, degree in indegree.items() if degree == 0)
    queue = deque(ready)
    order: list[int] = []
    while queue:
        producer = queue.popleft()
        order.append(producer)
        newly_ready: list[int] = []
        for consumer in producer_to_consumers[producer]:
            indegree[consumer] -= 1
            if indegree[consumer] == 0:
                newly_ready.append(consumer)
        for consumer in sorted(newly_ready):
            queue.append(consumer)

    if len(order) != len(components):  # defensive; SCC condensation is a DAG
        missing = sorted(set(range(len(components))) - set(order))
        order.extend(missing)
    return scc_id, order


def representative_cycle(component: list[str], requires: dict[str, list[str]]) -> list[str]:
    """Stable short cycle beginning at the component's smallest node id."""
    members = set(component)
    start = min(component)
    start_neighbors = [v for v in requires.get(start, []) if v in members]
    if start in start_neighbors:
        return [start, start]
    if not start_neighbors:
        return [start]

    queue: deque[str] = deque(sorted(start_neighbors))
    predecessor: dict[str, str] = {v: start for v in start_neighbors}
    visited = set(start_neighbors)

    while queue:
        node = queue.popleft()
        for neighbor in sorted(requires.get(node, [])):
            if neighbor == start:
                path_backward = [node]
                current = node
                while current != start:
                    current = predecessor[current]
                    path_backward.append(current)
                return list(reversed(path_backward)) + [start]
            if neighbor in members and neighbor not in visited:
                visited.add(neighbor)
                predecessor[neighbor] = node
                queue.append(neighbor)
    return [start]


def build_cycle_evidence(
    components: list[list[str]],
    requires: dict[str, list[str]],
) -> list[dict[str, Any]]:
    cycles: list[dict[str, Any]] = []
    for component in components:
        members = set(component)
        internal_edges = [
            [node, neighbor]
            for node in component
            for neighbor in sorted(requires.get(node, []))
            if neighbor in members
        ]
        is_cycle = len(component) > 1 or (
            len(component) == 1 and component[0] in requires.get(component[0], [])
        )
        if not is_cycle:
            continue
        path = representative_cycle(component, requires)
        digest = sha256_hex(
            canonical_bytes({"nodes": component, "edges": internal_edges, "path": path})
        )[:16]
        cycles.append(
            {
                "cycle_id": f"cycle-{digest}",
                "stable_digest": digest,
                "nodes": component,
                "size": len(component),
                "representative_path": path,
                "canonical_path": " -> ".join(path),
                "internal_edges": internal_edges,
            }
        )
    cycles.sort(key=lambda item: item["cycle_id"])
    return cycles
