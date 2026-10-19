"""Normalise native GuardDuty findings into scanner report findings.

Only metadata needed for triage is retained; raw source payloads and sensitive
resource configuration are intentionally excluded.
"""
from __future__ import annotations

from typing import Any
from dataclasses import dataclass

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


@dataclass(frozen=True)
class GuardDutyRegionResult:
    """Findings and completeness metadata for one selected region."""
    region: str
    findings: tuple[Finding, ...]
    detector_id: str | None
    pages_read: int
    truncated: bool


def fetch_guardduty_region_findings(client: Any, *, region: str, max_findings: int = 1000, max_pages: int = 100, page_size: int = 50, max_age_days: int | None = None, include_archived: bool = False) -> GuardDutyRegionResult:
    """Fetch one region with bounded pagination, stable identity and age filters.

    API errors intentionally propagate so callers can record coverage gaps.
    """
    from datetime import datetime, timedelta, timezone
    for name, value in (("max_findings", max_findings), ("max_pages", max_pages), ("page_size", page_size)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    if max_age_days is not None and (isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or max_age_days < 0):
        raise ValueError("max_age_days must be a non-negative integer or None")
    page_size = min(page_size, 50)
    detector_response = client.list_detectors()
    detector_ids = detector_response.get("DetectorIds", [])
    if not isinstance(detector_ids, list):
        raise ValueError("GuardDuty returned malformed DetectorIds")
    valid_ids = sorted(value for value in detector_ids if isinstance(value, str) and value)
    if not valid_ids:
        return GuardDutyRegionResult(region, (), None, 0, False)
    detector_id = valid_ids[0]
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days) if max_age_days is not None else None
    token = None
    seen_tokens: set[str] = set()
    seen_ids: set[str] = set()
    ids: list[str] = []
    pages_read = 0
    truncated = False
    while pages_read < max_pages and len(ids) < max_findings:
        kwargs: dict[str, Any] = {"DetectorId": detector_id, "MaxResults": page_size}
        if token:
            kwargs["NextToken"] = token
        response = client.list_findings(**kwargs)
        pages_read += 1
        page_ids = response.get("FindingIds", [])
        if not isinstance(page_ids, list):
            raise ValueError("GuardDuty returned malformed FindingIds")
        for value in page_ids:
            if isinstance(value, str) and value and value not in seen_ids:
                seen_ids.add(value)
                ids.append(value)
                if len(ids) >= max_findings:
                    break
        next_token = response.get("NextToken")
        if not next_token:
            token = None
            break
        if not isinstance(next_token, str) or next_token in seen_tokens:
            raise RuntimeError("GuardDuty pagination returned a repeated or invalid token")
        seen_tokens.add(next_token)
        token = next_token
    else:
        truncated = bool(token) or len(ids) >= max_findings
    if token:
        truncated = True
    converted: list[Finding] = []
    for offset in range(0, len(ids), 50):
        response = client.get_findings(DetectorId=detector_id, FindingIds=ids[offset:offset + 50])
        items = response.get("Findings", [])
        if not isinstance(items, list):
            raise ValueError("GuardDuty returned malformed Findings")
        for item in items:
            if not isinstance(item, dict):
                continue
            service = item.get("Service")
            archived = isinstance(service, dict) and service.get("Archived") is True
            if archived and not include_archived:
                continue
            created = item.get("CreatedAt")
            if cutoff is not None:
                if not isinstance(created, str):
                    continue
                try:
                    timestamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                if timestamp < cutoff:
                    continue
            finding = guardduty_to_finding(item, fallback_region=region, detector_id=detector_id)
            if finding is not None:
                converted.append(finding)
    converted.sort(key=lambda item: (item.source_id or "", item.resource, item.check_id))
    return GuardDutyRegionResult(region, tuple(converted), detector_id, pages_read, truncated)


def fetch_guardduty_findings(client_factory: Any, *, regions: list[str], max_findings_per_region: int = 1000, max_pages: int = 100, max_age_days: int | None = None, include_archived: bool = False) -> tuple[GuardDutyRegionResult, ...]:
    """Fetch explicitly selected regions in deterministic order."""
    if not isinstance(regions, list) or any(not isinstance(item, str) or not item.strip() for item in regions):
        raise ValueError("regions must be a list of non-empty region names")
    return tuple(fetch_guardduty_region_findings(
        client_factory(region), region=region, max_findings=max_findings_per_region,
        max_pages=max_pages, max_age_days=max_age_days, include_archived=include_archived,
    ) for region in sorted(set(regions)))
