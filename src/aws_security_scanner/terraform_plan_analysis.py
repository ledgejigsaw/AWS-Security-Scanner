"""Risk diagnostics for Terraform plan metadata already normalized by the provider."""
from __future__ import annotations

from typing import Any

from aws_security_scanner.models.resource import Resource

_SECURITY_TERMS = (
    "public", "encrypt", "kms", "logging", "versioning", "block_public_access",
    "ingress", "egress", "cidr", "principal", "policy", "https", "tls",
    "authorization", "security_group", "iam", "access_control",
)


def analyze_terraform_plan(resources: list[Resource]) -> list[dict[str, Any]]:
    """Return deterministic diagnostics for destructive changes and unknown controls.

    These diagnostics complement existing rules; they do not treat an unknown
    value as either compliant or non-compliant, and they do not execute Terraform.
    """
    diagnostics: list[dict[str, Any]] = []
    for resource in resources:
        attributes = resource.attributes if isinstance(resource.attributes, dict) else {}
        address = attributes.get("terraform_address")
        if not isinstance(address, str) or not address:
            address = resource.resource_id
        actions = attributes.get("terraform_plan_actions", [])
        actions = [item.lower() for item in actions if isinstance(item, str)] if isinstance(actions, list) else []
        action_set = set(actions)
        if attributes.get("terraform_removed") is True or "delete" in action_set:
            replacement = "create" in action_set
            diagnostics.append({
                "diagnostic_id": "TF-PLAN-REPLACEMENT" if replacement else "TF-PLAN-DESTROY",
                "severity": "HIGH" if replacement else "MEDIUM",
                "resource_address": address,
                "resource_type": resource.resource_type,
                "region": resource.region,
                "actions": sorted(action_set),
                "message": "Terraform plan replaces this resource; review data retention and downtime risk." if replacement else "Terraform plan removes this resource; review data retention and dependency impact.",
                "evidence": {"terraform_plan_actions": sorted(action_set), "terraform_removed": attributes.get("terraform_removed") is True},
            })

        unknown_values = attributes.get("terraform_unknown_attributes", [])
        if not isinstance(unknown_values, list):
            continue
        for path in sorted({item for item in unknown_values if isinstance(item, str) and item}):
            normalized = path.lower().replace("-", "_")
            if any(term in normalized for term in _SECURITY_TERMS):
                diagnostics.append({
                    "diagnostic_id": "TF-PLAN-UNKNOWN-SECURITY-VALUE",
                    "severity": "REVIEW",
                    "resource_address": address,
                    "resource_type": resource.resource_type,
                    "region": resource.region,
                    "attribute_path": path,
                    "actions": sorted(action_set),
                    "message": "A security-relevant Terraform value is unknown at plan time; configuration compliance cannot be confirmed from this value.",
                    "evidence": {"unknown_attribute_path": path},
                })
    return sorted(diagnostics, key=lambda item: (item["resource_address"], item["diagnostic_id"], item.get("attribute_path", "")))
