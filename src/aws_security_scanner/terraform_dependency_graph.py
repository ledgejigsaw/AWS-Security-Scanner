"""Deterministic dependency graph for offline Terraform HCL analysis."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aws_security_scanner.models.resource import Resource


@dataclass(frozen=True)
class DependencyEdge:
    """A resource dependency discovered from an HCL attribute reference."""

    source: str
    target: str
    attribute: str


@dataclass(frozen=True)
class DependencyGraph:
    """Stable graph snapshot plus unresolved edges and cycle membership."""

    nodes: tuple[dict[str, Any], ...]
    edges: tuple[DependencyEdge, ...]
    unresolved: tuple[dict[str, str], ...]
    cycle_nodes: tuple[str, ...]


def build_dependency_graph(resources: list[Resource]) -> DependencyGraph:
    """Build a graph from canonical addresses and extracted relationships.

    The graph does not infer provider-computed values. Relationship targets are
    accepted only when they identify a discovered resource address, with a
    unique suffix match permitted for a qualified address emitted by a child
    module. Ambiguous or missing targets remain unresolved.
    """
    address_to_resource = {
        resource.source_address: resource
        for resource in resources
        if resource.source_address and resource.resource_type != "terraform_hcl_unsupported"
    }
    addresses = set(address_to_resource)
    nodes = tuple(
        {
            "address": address,
            "resource_type": resource.resource_type,
            "source_file": resource.source_file,
        }
        for address, resource in sorted(address_to_resource.items())
    )
    edges: list[DependencyEdge] = []
    unresolved: list[dict[str, str]] = []
    adjacency: dict[str, list[str]] = {address: [] for address in addresses}

    for resource in resources:
        source = resource.source_address
        if not source or source not in addresses:
            continue
        for attribute, raw_target in sorted((resource.relationships or {}).items()):
            target = raw_target
            if target not in addresses:
                candidates = sorted(
                    address for address in addresses
                    if address.endswith("." + raw_target)
                )
                if len(candidates) == 1:
                    target = candidates[0]
                    resource.relationships[attribute] = target
                else:
                    unresolved.append({
                        "source": source,
                        "attribute": str(attribute),
                        "target": str(raw_target),
                        "reason": (
                            "ambiguous_target" if candidates else "target_not_discovered"
                        ),
                    })
                    continue
            edges.append(DependencyEdge(source=source, target=target, attribute=str(attribute)))
            adjacency[source].append(target)

    cycle_nodes = _find_cycle_nodes(adjacency)
    return DependencyGraph(
        nodes=nodes,
        edges=tuple(sorted(edges, key=lambda edge: (edge.source, edge.attribute, edge.target))),
        unresolved=tuple(sorted(unresolved, key=lambda item: (item["source"], item["attribute"], item["target"]))),
        cycle_nodes=tuple(sorted(cycle_nodes)),
    )


def _find_cycle_nodes(adjacency: dict[str, list[str]]) -> set[str]:
    """Return only nodes in directed cycles using iterative Kosaraju SCCs.

    Iterative traversal avoids Python recursion limits on large Terraform
    configurations. A node is cyclic only when its strongly connected
    component has multiple members or it has an explicit self-loop. Merely
    lying on a path between two separate cycles is not enough.
    """
    nodes = set(adjacency)
    reverse: dict[str, list[str]] = {node: [] for node in nodes}
    for source, targets in adjacency.items():
        for target in targets:
            if target in reverse:
                reverse[target].append(source)
    for neighbours in reverse.values():
        neighbours.sort()

    visited: set[str] = set()
    finish_order: list[str] = []
    for start in sorted(nodes):
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            stack.append((node, True))
            for target in sorted(adjacency.get(node, ()), reverse=True):
                if target in nodes and target not in visited:
                    visited.add(target)
                    stack.append((target, False))

    assigned: set[str] = set()
    cyclic: set[str] = set()
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[str] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for target in reverse.get(node, ()):
                if target not in assigned:
                    assigned.add(target)
                    stack.append(target)
        if len(component) > 1:
            cyclic.update(component)
        elif component and component[0] in adjacency.get(component[0], ()):
            cyclic.add(component[0])
    return cyclic


def dependency_diagnostics(graph: DependencyGraph, resources: list[Resource]) -> list[Resource]:
    """Create source-attributed diagnostic resources for unresolved edges/cycles."""
    by_address = {
        resource.source_address: resource
        for resource in resources
        if resource.source_address and resource.resource_type != "terraform_hcl_unsupported"
    }
    diagnostics: list[Resource] = []
    unresolved_by_source: dict[str, list[dict[str, str]]] = {}
    for edge in graph.unresolved:
        unresolved_by_source.setdefault(edge["source"], []).append(edge)

    for source, edges in sorted(unresolved_by_source.items()):
        original = by_address.get(source)
        if original is None:
            continue
        detail = "; ".join(
            f'{edge["attribute"]} -> {edge["target"]} ({edge["reason"]})'
            for edge in edges
        )
        diagnostics.append(Resource(
            resource_type="terraform_hcl_unsupported",
            resource_id=f"{source}#unresolved-dependency",
            attributes={
                "hcl_diagnostic": "dependency_reference_unresolved",
                "hcl_diagnostic_reason": detail,
                "hcl_diagnostic_details": edges,
            },
            source="terraform",
            region=original.region,
            source_file=original.source_file,
            source_address=f"{source}#unresolved-dependency",
        ))

    for source in graph.cycle_nodes:
        original = by_address.get(source)
        if original is None:
            continue
        diagnostics.append(Resource(
            resource_type="terraform_hcl_unsupported",
            resource_id=f"{source}#dependency-cycle",
            attributes={
                "hcl_diagnostic": "dependency_cycle",
                "hcl_diagnostic_reason": "Resource dependency graph contains a directed cycle.",
                "hcl_diagnostic_details": {"cycle_member": source},
            },
            source="terraform",
            region=original.region,
            source_file=original.source_file,
            source_address=f"{source}#dependency-cycle",
        ))
    return diagnostics
