"""Evidence-bounded network relationship graph and public-ingress assessment."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any, Iterable
from aws_security_scanner.models.resource import Resource

@dataclass(frozen=True)
class NetworkEdge:
    source: str
    target: str
    relationship: str
    provenance: str
    confidence: str = "observed"

@dataclass(frozen=True)
class PublicIngressAssessment:
    status: str
    confidence: str
    evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    path: tuple[str, ...] = ()

def build_network_relationship_graph(resources: Iterable[Resource]) -> dict[str, Any]:
    """Build a deterministic graph from relationships explicitly supplied by discovery."""
    items = list(resources)
    nodes = {}
    edges = set()
    for resource in items:
        key = resource.source_address or f"{resource.resource_type}:{resource.resource_id}"
        nodes[key] = {"address": key, "resource_type": resource.resource_type,
                      "resource_id": resource.resource_id, "region": resource.region, "source": resource.source}
    known = set(nodes)
    for resource in items:
        source = resource.source_address or f"{resource.resource_type}:{resource.resource_id}"
        for relation, raw_target in sorted((resource.relationships or {}).items()):
            target = raw_target
            if target not in known:
                candidates = sorted(node for node, item in nodes.items()
                                    if item["resource_id"] == raw_target or node.endswith("." + raw_target))
                if len(candidates) != 1:
                    continue
                target = candidates[0]
            edges.add((source, target, str(relation), "resource.relationships", "observed"))
    return {
        "schema_version": "1.0.0",
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": [asdict(NetworkEdge(*edge)) for edge in sorted(edges)],
        "limitations": [
            "Only explicitly discovered relationships are represented.",
            "Missing or ambiguous relationships are unknown, not proof of isolation.",
            "This graph does not establish packet-level reachability or model every route, NACL, security group, endpoint, firewall or load-balancer behaviour.",
        ],
    }

def assess_public_ingress(*, public_address: bool | None, route_to_internet_gateway: bool | None,
                          ingress_rule_permits_source: bool | None, attached_security_groups_known: bool,
                          network_acl_permits_path: bool | None, evidence: Iterable[str] = ()) -> PublicIngressAssessment:
    """Assess ingress only when each required signal is explicit; None means unknown."""
    signals = {"public_address": public_address, "route_to_internet_gateway": route_to_internet_gateway,
               "ingress_rule_permits_source": ingress_rule_permits_source,
               "network_acl_permits_path": network_acl_permits_path}
    missing = sorted(name for name, value in signals.items() if value is None)
    if not attached_security_groups_known:
        missing.append("attached_security_groups")
    observed = tuple(sorted(set(str(value) for value in evidence)))
    if missing:
        return PublicIngressAssessment("unknown", "insufficient", observed, tuple(sorted(missing)))
    if not all(signals.values()):
        return PublicIngressAssessment("blocked_or_not_public", "high", observed, ())
    return PublicIngressAssessment("public_ingress_supported_by_observed_evidence", "high", observed, ())

def network_edge_to_dict(edge: NetworkEdge) -> dict[str, str]:
    return asdict(edge)
