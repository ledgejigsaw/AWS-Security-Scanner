"""Deterministic, metadata-minimising resource graph export."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.models.resource import Resource


def _node_id(resource: Resource) -> str:
    identity = [
        resource.source,
        resource.account_id or "",
        resource.region or "",
        resource.resource_type,
        resource.resource_id,
    ]
    return "resource:" + json.dumps(identity, separators=(",", ":"), ensure_ascii=True)


def build_resource_graph(
    resources: list[Resource],
    findings: list[Finding] | None = None,
) -> dict[str, Any]:
    """Build a stable graph using only known relationships and safe metadata."""
    findings = findings or []
    ids = {_node_id(resource): resource for resource in resources}
    by_type_and_name = {
        (resource.resource_type, resource.resource_id): _node_id(resource)
        for resource in resources
    }
    by_id: dict[str, list[str]] = {}
    for resource in resources:
        by_id.setdefault(resource.resource_id, []).append(_node_id(resource))

    linked_findings: dict[str, list[dict[str, str]]] = {node_id: [] for node_id in ids}
    for finding in findings:
        candidates = [
            node_id
            for node_id, resource in ids.items()
            if resource.resource_id == finding.resource
            and (finding.region is None or resource.region == finding.region)
            and (finding.account_id is None or resource.account_id == finding.account_id)
        ]
        if len(candidates) == 1:
            linked_findings[candidates[0]].append({
                "check_id": finding.check_id,
                "severity": finding.severity.value,
            })

    nodes = []
    for node_id, resource in sorted(ids.items()):
        node = {
            "id": node_id,
            "node_type": "resource",
            "provider": resource.source,
            "resource_type": resource.resource_type,
            "resource_id": resource.resource_id,
            "region": resource.region,
            "account_id": resource.account_id,
            "findings": sorted(
                linked_findings[node_id],
                key=lambda item: (item["check_id"], item["severity"]),
            ),
        }
        nodes.append(node)

    edges: list[dict[str, str]] = []
    unresolved: list[dict[str, str]] = []
    for node_id, resource in sorted(ids.items()):
        relationships = resource.relationships or {}
        for attribute, reference in sorted(relationships.items()):
            if not isinstance(reference, str) or not reference:
                unresolved.append({
                    "source": node_id,
                    "relationship": str(attribute),
                    "status": "unknown",
                    "reference": "<non-string-reference>",
                })
                continue
            target = None
            if "." in reference:
                resource_type, resource_name = reference.split(".", 1)
                target = by_type_and_name.get((resource_type, resource_name))
            if target is None:
                matching_ids = by_id.get(reference, [])
                if len(matching_ids) == 1:
                    target = matching_ids[0]
            if target is None:
                safe_reference = "<unresolved-expression>" if "${" in reference else reference[:256]
                unresolved.append({
                    "source": node_id,
                    "relationship": str(attribute),
                    "status": "unknown",
                    "reference": safe_reference,
                })
                continue
            provenance = {
                "terraform": "terraform_static_reference",
                "terraform-hcl": "terraform_hcl_static_reference",
                "aws": "provider_relationship",
                "fixture": "fixture_relationship",
            }.get(resource.source, "normalised_resource_relationship")
            edges.append({
                "source": node_id,
                "target": target,
                "relationship": str(attribute),
                "provenance": provenance,
                "confidence": "high",
            })

    return {
        "schema_version": "1.0",
        "scope": "observed_resources_and_explicit_relationships",
        "limitations": [
            "Only explicitly represented relationships are emitted.",
            "An absent edge does not prove network reachability or isolation.",
            "Raw resource attributes, policies, secrets and object contents are not exported.",
            "Unresolved references are listed separately with unknown status.",
        ],
        "nodes": nodes,
        "edges": sorted(
            edges,
            key=lambda item: (item["source"], item["target"], item["relationship"]),
        ),
        "unresolved_relationships": sorted(
            unresolved,
            key=lambda item: (item["source"], item["relationship"], item["reference"]),
        ),
    }


def write_resource_graph(
    resources: list[Resource],
    findings: list[Finding],
    output_path: str | Path,
) -> None:
    """Write graph JSON deterministically."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_resource_graph(resources, findings)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
