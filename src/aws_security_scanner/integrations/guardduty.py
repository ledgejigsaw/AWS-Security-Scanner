"""Normalise native GuardDuty findings into scanner report findings.

Only metadata needed for triage is retained; raw source payloads and sensitive
resource configuration are intentionally excluded.
"""
from __future__ import annotations

from typing import Any

from aws_security_scanner.models.finding import Finding, Severity


def _severity(value: Any) -> Severity:
    """Map GuardDuty's numeric 0-10 severity conservatively."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return Severity.INFO
    if value >= 9:
        return Severity.CRITICAL
    if value >= 7:
        return Severity.HIGH
    if value >= 4:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return Severity.INFO


def _resource_identifier(resource: Any, fallback: str) -> str:
    if not isinstance(resource, dict):
        return fallback
    for key in ("InstanceDetails", "AccessKeyDetails", "S3BucketDetails", "EksClusterDetails",
                "KubernetesDetails", "ContainerDetails", "RdsDbInstanceDetails",
                "LambdaDetails", "EcsClusterDetails", "ResourceDetails"):
        value = resource.get(key)
        if isinstance(value, dict):
            for field in ("InstanceId", "AccessKeyId", "Name", "ClusterName", "Uid", "DbInstanceIdentifier",
                          "FunctionName", "ClusterArn", "ResourceId"):
                candidate = value.get(field)
                if isinstance(candidate, str) and candidate:
                    return candidate
        elif isinstance(value, list):
            names = []
            for item in value[:5]:
                if not isinstance(item, dict):
                    continue
                candidate = item.get("Name") or item.get("Arn") or item.get("BucketName")
                if isinstance(candidate, str) and candidate:
                    names.append(candidate)
            if names:
                return ", ".join(names)
    resource_id = resource.get("ResourceId")
    return resource_id if isinstance(resource_id, str) and resource_id else fallback


def guardduty_to_finding(
    item: dict[str, Any],
    *,
    fallback_region: str | None = None,
    detector_id: str | None = None,
) -> Finding | None:
    """Convert one GuardDuty finding while retaining stable source identity."""
    if not isinstance(item, dict):
        return None
    source_id = item.get("Id")
    if not isinstance(source_id, str) or not source_id.strip():
        return None

    title = item.get("Title")
    if not isinstance(title, str) or not title.strip():
        title = item.get("Type")
    if not isinstance(title, str) or not title.strip():
        title = "Untitled AWS GuardDuty finding"
    description = item.get("Description")
    if not isinstance(description, str) or not description.strip():
        description = "The source did not provide a description."

    region = item.get("Region")
    if not isinstance(region, str) or not region:
        region = fallback_region
    account_id = item.get("AccountId")
    if not isinstance(account_id, str) or not account_id:
        account_id = None

    product = detector_id or "GuardDuty"
    resource_id = _resource_identifier(item.get("Resource"), source_id)
    return Finding(
        check_id="AWS-GD-NATIVE",
        severity=_severity(item.get("Severity")),
        service="GuardDuty",
        resource=resource_id,
        title=title,
        description=description,
        remediation="Review this finding and its remediation guidance in the GuardDuty console.",
        region=region,
        evidence=f"Imported from AWS GuardDuty; source finding ID: {source_id}",
        account_id=account_id,
        source_type="guardduty",
        source_id=source_id,
        source_product=product,
        first_observed_at=item.get("CreatedAt") if isinstance(item.get("CreatedAt"), str) else None,
        last_observed_at=item.get("UpdatedAt") if isinstance(item.get("UpdatedAt"), str) else None,
    )
