"""Normalise native AWS Security Hub findings into scanner report findings.

Only finding metadata needed for triage is retained. Raw product fields and
full source payloads are intentionally excluded from reports.
"""
from __future__ import annotations

from typing import Any

from aws_security_scanner.models.finding import Finding, Severity


SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
    "INFO": Severity.INFO,
}


def securityhub_to_finding(
    item: dict[str, Any],
    *,
    fallback_region: str | None = None,
) -> Finding | None:
    """Convert one AWS Security Finding Format item to a report Finding."""
    if not isinstance(item, dict):
        return None

    source_id = item.get("Id")
    if not isinstance(source_id, str) or not source_id.strip():
        return None

    product_arn = item.get("ProductArn")
    product_arn = product_arn if isinstance(product_arn, str) else None
    product_name = item.get("ProductName")
    product_name = product_name if isinstance(product_name, str) and product_name else "Security Hub"

    severity_data = item.get("Severity")
    if not isinstance(severity_data, dict):
        severity_data = {}
    severity_label = severity_data.get("Label")
    severity = SEVERITY_MAP.get(severity_label, Severity.INFO) if isinstance(severity_label, str) else Severity.INFO

    resources = item.get("Resources")
    if not isinstance(resources, list):
        resources = []
    resource_ids = [
        resource.get("Id")
        for resource in resources
        if isinstance(resource, dict) and isinstance(resource.get("Id"), str) and resource.get("Id")
    ]
    resource_id = ", ".join(resource_ids[:5]) if resource_ids else source_id

    remediation = item.get("Remediation")
    if not isinstance(remediation, dict):
        remediation = {}
    recommendation = remediation.get("Recommendation")
    if not isinstance(recommendation, dict):
        recommendation = {}
    remediation_text = recommendation.get("Text")
    if not isinstance(remediation_text, str) or not remediation_text.strip():
        remediation_text = "Review this finding and its remediation guidance in AWS Security Hub."

    title = item.get("Title")
    if not isinstance(title, str) or not title.strip():
        title = "Untitled AWS Security Hub finding"
    description = item.get("Description")
    if not isinstance(description, str) or not description.strip():
        description = "The source did not provide a description."

    region = item.get("Region")
    if not isinstance(region, str) or not region:
        region = fallback_region

    account_id = item.get("AwsAccountId")
    if not isinstance(account_id, str) or not account_id:
        account_id = None

    first_observed = item.get("FirstObservedAt")
    last_observed = item.get("LastObservedAt")
    return Finding(
        check_id="AWS-SHUB-NATIVE",
        severity=severity,
        service=product_name,
        resource=resource_id,
        title=title,
        description=description,
        remediation=remediation_text,
        region=region,
        evidence=f"Imported from AWS Security Hub; source finding ID: {source_id}",
        account_id=account_id,
        source_type="security_hub",
        source_id=source_id,
        source_product=product_arn,
        first_observed_at=first_observed if isinstance(first_observed, str) else None,
        last_observed_at=last_observed if isinstance(last_observed, str) else None,
    )
