"""Normalise IAM Access Analyzer findings into report findings.

Only stable identifiers and small amounts of triage metadata are retained.
Resource policy documents and full finding payloads are not exported.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from aws_security_scanner.models.finding import Finding, Severity


def _timestamp(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return value if isinstance(value, str) else None


def access_analyzer_to_finding(
    item: dict[str, Any],
    *,
    fallback_region: str | None = None,
) -> Finding | None:
    """Convert an active Access Analyzer finding with stable source identity."""
    if not isinstance(item, dict):
        return None
    source_id = item.get("id")
    if not isinstance(source_id, str) or not source_id.strip():
        return None
    status = item.get("status")
    if isinstance(status, str) and status.upper() != "ACTIVE":
        return None

    finding_type = item.get("findingType")
    finding_type = finding_type if isinstance(finding_type, str) else "Unknown"
    is_public = item.get("isPublic") if isinstance(item.get("isPublic"), bool) else None
    if finding_type == "ExternalAccess" and is_public is True:
        severity = Severity.HIGH
    elif finding_type == "ExternalAccess":
        severity = Severity.MEDIUM
    elif finding_type == "UnusedAccess":
        severity = Severity.LOW
    else:
        severity = Severity.INFO

    resource = item.get("resource")
    resource = resource if isinstance(resource, str) and resource else source_id
    resource_type = item.get("resourceType")
    resource_type = resource_type if isinstance(resource_type, str) else "AWS resource"
    title = f"IAM Access Analyzer: {finding_type} for {resource_type}"
    if is_public is True:
        title += " (public access)"

    account_id = item.get("resourceOwnerAccount")
    if not isinstance(account_id, str) or not account_id:
        account_id = None
    analyzer_arn = item.get("analyzerArn")
    if not isinstance(analyzer_arn, str) or not analyzer_arn:
        analyzer_arn = "IAM Access Analyzer"
    region = item.get("region")
    if not isinstance(region, str) or not region:
        region = fallback_region

    evidence_parts = [
        f"findingType={finding_type}",
        f"status={status or 'unknown'}",
    ]
    if is_public is not None:
        evidence_parts.append(f"isPublic={str(is_public).lower()}")

    return Finding(
        check_id="AWS-AA-NATIVE",
        severity=severity,
        service="IAM Access Analyzer",
        resource=resource,
        title=title,
        description=(
            "IAM Access Analyzer reported an active access-analysis finding. "
            "The severity is a conservative triage mapping, not a statement that "
            "the access is necessarily unintended."
        ),
        remediation=(
            "Review the finding in IAM Access Analyzer and verify whether the "
            "reported access is intended. Restrict the resource policy or access "
            "configuration only after confirming the required access model."
        ),
        region=region,
        evidence=(
            "Imported from IAM Access Analyzer; source finding ID: "
            f"{source_id}; " + "; ".join(evidence_parts)
        ),
        account_id=account_id,
        source_type="access_analyzer",
        source_id=source_id,
        source_product=analyzer_arn,
        first_observed_at=_timestamp(item.get("createdAt")),
        last_observed_at=_timestamp(item.get("updatedAt")),
    )
