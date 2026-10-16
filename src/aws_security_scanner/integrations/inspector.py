"""Normalise Amazon Inspector findings into scanner report findings.

Only stable source identity and selected triage metadata are retained; full
resource payloads and package inventories are not copied into reports.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from aws_security_scanner.models.finding import Finding, Severity


def _timestamp(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return value if isinstance(value, str) else None


def _severity(value: Any) -> Severity:
    if not isinstance(value, str):
        return Severity.INFO
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFORMATIONAL": Severity.INFO,
        "UNTRIAGED": Severity.INFO,
    }.get(value.upper(), Severity.INFO)


def inspector_to_finding(
    item: dict[str, Any],
    *,
    fallback_region: str | None = None,
) -> Finding | None:
    """Convert one active Inspector finding with stable source provenance."""
    if not isinstance(item, dict):
        return None
    source_id = item.get("findingArn")
    if not isinstance(source_id, str) or not source_id.strip():
        return None
    status = item.get("status")
    if isinstance(status, str) and status.upper() != "ACTIVE":
        return None

    title = item.get("title")
    title = title if isinstance(title, str) and title.strip() else "Untitled Amazon Inspector finding"
    description = item.get("description")
    description = description if isinstance(description, str) and description.strip() else (
        "Amazon Inspector reported an active security finding."
    )
    resources = item.get("resources")
    resource = None
    if isinstance(resources, list):
        for candidate in resources:
            if isinstance(candidate, dict):
                resource = candidate.get("id") or candidate.get("resourceId")
                if isinstance(resource, str) and resource:
                    break
    if not isinstance(resource, str) or not resource:
        resource = source_id

    region = item.get("region")
    if not isinstance(region, str) or not region:
        region = fallback_region
    account_id = item.get("awsAccountId")
    if not isinstance(account_id, str) or not account_id:
        account_id = None
    finding_type = item.get("type")
    finding_type = finding_type if isinstance(finding_type, str) else "unknown"

    return Finding(
        check_id="AWS-INSPECTOR-NATIVE",
        severity=_severity(item.get("severity")),
        service="Amazon Inspector",
        resource=resource,
        title=title,
        description=description,
        remediation="Review the finding and remediation recommendation in Amazon Inspector.",
        region=region,
        evidence=f"Imported from Amazon Inspector; source finding ARN: {source_id}; type={finding_type}",
        account_id=account_id,
        source_type="inspector",
        source_id=source_id,
        source_product="Amazon Inspector",
        first_observed_at=_timestamp(item.get("firstObservedAt")),
        last_observed_at=_timestamp(item.get("lastObservedAt") or item.get("updatedAt")),
    )
