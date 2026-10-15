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


_ATTRIBUTE_TARGET_TYPES = {
    "vpc_id": {"aws_vpc"},
    "subnet_id": {"aws_subnet"},
    "security_group_id": {"aws_security_group"},
    "security_group_ids": {"aws_security_group"},
    "attached_instance_ids": {"aws_instance"},
    "instance_id": {"aws_instance"},
    "target_bucket": {"aws_s3_bucket"},
    "bucket_name": {"aws_s3_bucket"},
    "kms_key_id": {"aws_kms_key"},
    "route_table_id": {"aws_route_table"},
}


def _attribute_relationships(value: Any, path: str = "") -> list[tuple[str, str, set[str]]]:
    """Extract only explicitly named ID attributes with known target semantics."""
    result: list[tuple[str, str, set[str]]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            target_types = _ATTRIBUTE_TARGET_TYPES.get(str(key))
            if target_types:
                candidates = nested if isinstance(nested, list) else [nested]
                for candidate in candidates:
                    if isinstance(candidate, str) and candidate and "${" not in candidate:
                        result.append((child_path, candidate, target_types))
            else:
                result.extend(_attribute_relationships(nested, child_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            result.extend(_attribute_relationships(nested, f"{path}[{index}]"))
    return result


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
        relationships = dict(resource.relationships or {})
        explicit_relationships = {
            (attribute, reference): None
            for attribute, reference in relationships.items()
        }
        for attribute, reference, target_types in _attribute_relationships(resource.attributes):
            explicit_relationships.setdefault((attribute, reference), target_types)
        for (attribute, reference), target_types in sorted(explicit_relationships.items()):
            if not isinstance(reference, str) or not reference:
                unresolved.append({
                    "source": node_id,
                    "relationship": str(attribute),
                    "status": "unknown",
                    "reference": "<non-string-reference>",
                })
                continue
            target = None
            if target_types is None and "." in reference:
                resource_type, resource_name = reference.split(".", 1)
                target = by_type_and_name.get((resource_type, resource_name))
            elif target_types is not None:
                matching_ids = [
                    candidate_id for candidate_id, candidate in ids.items()
                    if candidate.resource_type in target_types
                    and candidate.resource_id == reference
                    and candidate.source == resource.source
                    and (candidate.region is None or resource.region is None or candidate.region == resource.region)
                    and (candidate.account_id is None or resource.account_id is None or candidate.account_id == resource.account_id)
                ]
                if len(matching_ids) == 1:
                    target = matching_ids[0]
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
            provenance = (
                "normalised_attribute_reference"
                if target_types is not None
                else {
                    "terraform": "terraform_static_reference",
                    "terraform-hcl": "terraform_hcl_static_reference",
                    "aws": "provider_relationship",
                    "fixture": "fixture_relationship",
                }.get(resource.source, "normalised_resource_relationship")
            )
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
