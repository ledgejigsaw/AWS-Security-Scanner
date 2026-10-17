"""Conservative attack-path candidates over the exported resource graph.

This module reports graph paths as candidates for analyst review. It does not
model network reachability, IAM evaluation, runtime state, or exploitability.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def find_attack_path_candidates(
    graph: dict[str, Any],
    *,
    entry_check_ids: set[str],
    target_check_ids: set[str] | None = None,
    target_resource_types: set[str] | None = None,
    max_depth: int = 6,
    max_paths: int = 100,
) -> list[dict[str, Any]]:
    """Return deterministic candidate paths from entry findings to target findings/types.

    Graph edges are traversed in their declared source-to-target direction. Entry
    nodes must carry a check ID in ``entry_check_ids``. A destination qualifies
    when it carries a configured target check or its resource type is selected.
    Paths are simple (no repeated node), depth- and result-bounded, and labelled
    as candidates rather than proof of exploitability.
    """
    if max_depth < 1 or max_paths < 1:
        raise ValueError("max_depth and max_paths must be positive integers")
    nodes_raw = graph.get("nodes", [])
    edges_raw = graph.get("edges", [])
    if not isinstance(nodes_raw, list) or not isinstance(edges_raw, list):
        raise ValueError("graph nodes and edges must be lists")

    nodes: dict[str, dict[str, Any]] = {}
    for node in nodes_raw:
        if isinstance(node, dict) and isinstance(node.get("id"), str):
            nodes[node["id"]] = node
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in edges_raw:
        if not isinstance(edge, dict):
            continue
        source, target = edge.get("source"), edge.get("target")
        if isinstance(source, str) and isinstance(target, str) and source in nodes and target in nodes:
            adjacency[source].append((target, str(edge.get("relationship", "relationship"))))
    for source in adjacency:
        adjacency[source] = sorted(set(adjacency[source]))

    target_check_ids = target_check_ids or set()
    target_resource_types = target_resource_types or set()

    def checks(node: dict[str, Any]) -> set[str]:
        values = node.get("findings", [])
        return {item["check_id"] for item in values if isinstance(item, dict) and isinstance(item.get("check_id"), str)} if isinstance(values, list) else set()

    entries = sorted(node_id for node_id, node in nodes.items() if checks(node) & entry_check_ids)
    candidates: list[dict[str, Any]] = []
    for start in entries:
        # Iterative DFS keeps large graphs safe from Python recursion limits.
        stack: list[tuple[str, list[str], list[dict[str, str]]]] = [(start, [start], [])]
        while stack and len(candidates) < max_paths:
            current, path, path_edges = stack.pop()
            if len(path) > 1:
                destination = nodes[current]
                destination_checks = sorted(checks(destination) & target_check_ids)
                is_target = bool(destination_checks) or destination.get("resource_type") in target_resource_types
                if is_target:
                    candidates.append({
                        "classification": "potential_attack_path_candidate",
                        "confidence": "unverified_relationship_path",
                        "entry_node": start,
                        "target_node": current,
                        "node_ids": path,
                        "resource_types": [nodes[item].get("resource_type") for item in path],
                        "relationships": path_edges,
                        "entry_check_ids": sorted(checks(nodes[start]) & entry_check_ids),
                        "target_check_ids": destination_checks,
                        "limitations": [
                            "Graph edges represent recorded relationships, not proven network reachability.",
                            "IAM effective permissions and runtime exploitability are not evaluated.",
                            "A candidate path requires analyst validation before risk conclusions are drawn.",
                        ],
                    })
                    continue
            if len(path) - 1 >= max_depth:
                continue
            next_steps = adjacency.get(current, [])
            # Reverse push order so emitted DFS paths are lexically deterministic.
            for target, relationship in reversed(next_steps):
                if target in path:
                    continue
                stack.append((target, path + [target], path_edges + [{"relationship": relationship, "source": current, "target": target}]))
        if len(candidates) >= max_paths:
            break
    return candidates
