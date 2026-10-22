"""Deterministic dependency graph for offline Terraform HCL analysis."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
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
        stack: list[tuple[str, Any]] = [
            (start, iter(sorted(target for target in adjacency.get(start, ()) if target in nodes)))
        ]
        while stack:
            node, neighbours = stack[-1]
            try:
                target = next(neighbours)
            except StopIteration:
                finish_order.append(node)
                stack.pop()
                continue
            if target not in visited:
                visited.add(target)
                stack.append((target, iter(sorted(
                    child for child in adjacency.get(target, ()) if child in nodes
                ))))

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


_REFERENCE = re.compile(r"^(?:\$\{)?(?P<address>(?:module\.[A-Za-z0-9_-]+\.)*(?:aws_[A-Za-z0-9_]+|[A-Za-z0-9_]+)\.[A-Za-z0-9_-]+)\.(?P<attribute>[A-Za-z0-9_-]+)(?:\})?$")


def resolve_static_resource_attributes(resources: list[Resource]) -> dict[str, Any]:
    """Resolve exact references to explicitly present scalar attributes only."""
    by_address = {
        resource.source_address: resource for resource in resources
        if resource.source_address and resource.resource_type != "terraform_hcl_unsupported"
    }
    unresolved: list[dict[str, str]] = []
    resolved: list[dict[str, str]] = []

    def visit(value: Any, resource: Resource, path: str) -> Any:
        if isinstance(value, dict):
            return {key: visit(item, resource, f"{path}.{key}" if path else str(key)) for key, item in value.items()}
        if isinstance(value, list):
            return [visit(item, resource, f"{path}[{index}]") for index, item in enumerate(value)]
        if not isinstance(value, str):
            return value
        match = _REFERENCE.fullmatch(value.strip())
        if not match:
            return value
        address, attribute = match.group("address"), match.group("attribute")
        target = by_address.get(address)
        if target is None:
            unresolved.append({"source": resource.source_address or resource.resource_id, "attribute": path, "reference": value, "reason": "target_not_discovered"})
            return value
        if attribute not in target.attributes:
            unresolved.append({"source": resource.source_address or resource.resource_id, "attribute": path, "reference": value, "reason": "attribute_not_explicitly_observed"})
            return value
        candidate = target.attributes[attribute]
        if isinstance(candidate, str) and (chr(36) + "{" in candidate or re.search(r"\b(?:var|local|module)\.", candidate)):
            unresolved.append({"source": resource.source_address or resource.resource_id, "attribute": path, "reference": value, "reason": "target_value_is_expression"})
            return value
        if isinstance(candidate, (dict, list)) or candidate is None:
            unresolved.append({"source": resource.source_address or resource.resource_id, "attribute": path, "reference": value, "reason": "target_value_not_static_scalar"})
            return value
        resolved.append({"source": resource.source_address or resource.resource_id, "attribute": path, "reference": value, "target": address + "." + attribute})
        return candidate

    for resource in resources:
        if resource.resource_type == "terraform_hcl_unsupported":
            continue
        own_unresolved_start = len(unresolved)
        resource.attributes = visit(resource.attributes, resource, "")
        own_unresolved = unresolved[own_unresolved_start:]
        if own_unresolved:
            prior = resource.attributes.get("hcl_unresolved_expressions", [])
            if not isinstance(prior, list):
                prior = [str(prior)]
            extra = [f"{item['attribute']}: {item['reference']} ({item['reason']})" for item in own_unresolved]
            resource.attributes["hcl_unresolved_expressions"] = sorted(set(prior + extra))
    return {
        "resolved": sorted(resolved, key=lambda item: (item["source"], item["attribute"], item["target"])),
        "unresolved": sorted(unresolved, key=lambda item: (item["source"], item["attribute"], item["reference"])),
    }


def dependency_graph_to_dict(graph: DependencyGraph) -> dict[str, Any]:
    """Serialise graph nodes, edges, unresolved references and cycle membership."""
    return {
        "schema_version": "1.0.0",
        "nodes": list(graph.nodes),
        "edges": [asdict(edge) for edge in graph.edges],
        "unresolved": list(graph.unresolved),
        "cycle_nodes": list(graph.cycle_nodes),
        "limitations": [
            "Only extracted resource references are represented.",
            "Static values are propagated only from explicit scalar attributes; provider-computed values remain unresolved.",
            "This is a dependency graph, not a complete Terraform evaluator.",
        ],
    }
