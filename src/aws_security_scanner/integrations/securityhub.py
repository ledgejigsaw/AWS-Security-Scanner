"""Normalise native AWS Security Hub findings into scanner report findings.

Only finding metadata needed for triage is retained. Raw product fields and
full source payloads are intentionally excluded from reports.
"""
from __future__ import annotations

from typing import Any
from dataclasses import dataclass

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
    # Preserve concise control/status provenance without embedding the full
    # AWS Security Finding Format payload in reports.
    generator_id = item.get("GeneratorId")
    compliance = item.get("Compliance")
    compliance = compliance if isinstance(compliance, dict) else {}
    workflow = item.get("Workflow")
    workflow = workflow if isinstance(workflow, dict) else {}
    record_state = item.get("RecordState")
    workflow_status = workflow.get("Status")
    compliance_status = compliance.get("Status")
    provenance = [f"Imported from AWS Security Hub; source finding ID: {source_id}"]
    if isinstance(generator_id, str) and generator_id:
        provenance.append(f"generator/control: {generator_id}")
    if isinstance(compliance_status, str) and compliance_status:
        provenance.append(f"compliance status: {compliance_status}")
    if isinstance(workflow_status, str) and workflow_status:
        provenance.append(f"workflow status: {workflow_status}")
    if isinstance(record_state, str) and record_state:
        provenance.append(f"record state: {record_state}")
    return Finding(
        check_id="AWS-SHUB-NATIVE",
        severity=severity,
        service=product_name,
        resource=resource_id,
        title=title,
        description=description,
        remediation=remediation_text,
        region=region,
        evidence="; ".join(provenance),
        account_id=account_id,
        source_type="security_hub",
        source_id=source_id,
        source_product=product_arn,
        first_observed_at=first_observed if isinstance(first_observed, str) else None,
        last_observed_at=last_observed if isinstance(last_observed, str) else None,
    )


@dataclass(frozen=True)
class SecurityHubFetchResult:
    """Bounded Security Hub query result with explicit truncation metadata."""
    findings: tuple[Finding, ...]
    pages_read: int
    truncated: bool


def fetch_securityhub_findings(client: Any, *, region: str | None = None, filters: dict[str, Any] | None = None, max_findings: int = 1000, max_pages: int = 100, page_size: int = 100) -> SecurityHubFetchResult:
    """Fetch ASFF findings with bounded pagination; API errors propagate."""
    for name, value in (("max_findings", max_findings), ("max_pages", max_pages), ("page_size", page_size)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    page_size = min(page_size, 100)
    token = None
    seen_tokens: set[str] = set()
    seen_ids: set[str] = set()
    findings: list[Finding] = []
    pages_read = 0
    truncated = False
    while pages_read < max_pages and len(findings) < max_findings:
        kwargs: dict[str, Any] = {"MaxResults": page_size}
        if filters:
            kwargs["Filters"] = filters
        if token:
            kwargs["NextToken"] = token
        response = client.get_findings(**kwargs)
        pages_read += 1
        items = response.get("Findings", [])
        if not isinstance(items, list):
            raise ValueError("Security Hub returned malformed Findings")
        for item in items:
            if not isinstance(item, dict):
                continue
            source_id = item.get("Id")
            if not isinstance(source_id, str) or not source_id or source_id in seen_ids:
                continue
            seen_ids.add(source_id)
            finding = securityhub_to_finding(item, fallback_region=region)
            if finding is not None:
                findings.append(finding)
                if len(findings) >= max_findings:
                    break
        next_token = response.get("NextToken")
        if not next_token:
            token = None
            break
        if not isinstance(next_token, str) or next_token in seen_tokens:
            raise RuntimeError("Security Hub pagination returned a repeated or invalid token")
        seen_tokens.add(next_token)
        token = next_token
    else:
        truncated = bool(token) or len(findings) >= max_findings
    if token:
        truncated = True
    return SecurityHubFetchResult(tuple(findings), pages_read, truncated)
