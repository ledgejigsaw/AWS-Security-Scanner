"""Normalise native Amazon Macie findings into scanner report findings.

Only identifiers and selected triage metadata are retained; finding payloads
and sensitive-data samples are never copied into reports.
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
    }.get(value.upper(), Severity.INFO)


def macie_to_finding(
    item: dict[str, Any],
    *,
    fallback_region: str | None = None,
) -> Finding | None:
    """Convert one Macie finding to a canonical finding without sensitive samples."""
    if not isinstance(item, dict):
        return None
    source_id = item.get("id")
    if not isinstance(source_id, str) or not source_id.strip():
        return None
    if item.get("archived") is True:
        return None

    severity_data = item.get("severity")
    if not isinstance(severity_data, dict):
        severity_data = {}
    severity = _severity(severity_data.get("description"))

    resource = item.get("resourcesAffected")
    if not isinstance(resource, dict):
        resource = {}
    s3_details = resource.get("s3Object")
    if not isinstance(s3_details, dict):
        s3_details = {}
    resource_id = s3_details.get("path") or resource.get("s3Bucket")
    if not isinstance(resource_id, str) or not resource_id:
        resource_id = source_id

    title = item.get("title")
    if not isinstance(title, str) or not title.strip():
        title = "Amazon Macie sensitive-data finding"
    description = item.get("description")
    if not isinstance(description, str) or not description.strip():
        description = "Amazon Macie reported a sensitive-data security finding."

    region = item.get("region")
    if not isinstance(region, str) or not region:
        region = fallback_region
    account_id = item.get("accountId")
    if not isinstance(account_id, str) or not account_id:
        account_id = None

    return Finding(
        check_id="AWS-MACIE-NATIVE",
        severity=severity,
        service="Amazon Macie",
        resource=resource_id,
        title=title,
        description=description,
        remediation="Review the finding and affected S3 resource in Amazon Macie. Do not include sensitive-data samples in tickets or reports.",
        region=region,
        evidence=f"Imported from Amazon Macie; source finding ID: {source_id}",
        account_id=account_id,
        source_type="macie",
        source_id=source_id,
        source_product="Amazon Macie",
        first_observed_at=_timestamp(item.get("createdAt")),
        last_observed_at=_timestamp(item.get("updatedAt")),
    )
