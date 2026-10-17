"""Map canonical findings to the OCSF Detection Finding event class."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from aws_security_scanner.models.finding import Finding, Severity


OCSF_SCHEMA_VERSION = "1.7.0"
OCSF_CLASS_UID = 2004  # Detection Finding; Security Finding (2001) is deprecated.
SEVERITY_IDS = {
    Severity.INFO: (1, "Informational"),
    Severity.LOW: (2, "Low"),
    Severity.MEDIUM: (3, "Medium"),
    Severity.HIGH: (4, "High"),
    Severity.CRITICAL: (5, "Critical"),
}


def _epoch_milliseconds(value: str | None, fallback: int) -> int:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return fallback
        return int(parsed.timestamp() * 1000)
    except (TypeError, ValueError, OverflowError):
        return fallback


def _finding_uid(finding: Finding) -> str:
    identity = {
        "check_id": finding.check_id,
        "resource": finding.resource,
        "account_id": finding.account_id,
        "region": finding.region,
        "source_type": finding.source_type,
        "source_id": finding.source_id,
        "source_product": finding.source_product,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_ocsf_report(
    findings: list[Finding],
    *,
    generated_at: datetime | None = None,
) -> list[dict]:
    """Return OCSF 1.7.0 Detection Finding events in deterministic input order."""
    generated = generated_at or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware.")
    generated_ms = int(generated.timestamp() * 1000)
    events = []

    for finding in findings:
        severity_id, severity_name = SEVERITY_IDS[finding.severity]
        event_time = _epoch_milliseconds(
            finding.last_observed_at or finding.first_observed_at,
            generated_ms,
        )
        uid = _finding_uid(finding)
        resource = {
            "uid": finding.resource,
            "name": finding.resource,
            "type": finding.service,
        }
        if finding.region:
            resource["region"] = finding.region
        event = {
            "class_uid": OCSF_CLASS_UID,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "type_uid": OCSF_CLASS_UID * 100 + 1,
            "type_name": "Detection Finding: Create",
            "time": event_time,
            "severity_id": severity_id,
            "severity": severity_name,
            "status_id": 1,
            "status": "New",
            "message": f"{finding.title}: {finding.description}",
            "metadata": {
                "version": OCSF_SCHEMA_VERSION,
                "product": {
                    "name": "AWS Security Scanner",
                    "vendor_name": "ledgejigsaw",
                    "version": "0.1.0",
                },
            },
            "finding_info": {
                "uid": uid,
                "title": finding.title,
                "desc": finding.description,
                "created_time": event_time,
                "analytic": {
                    "uid": finding.check_id,
                    "name": finding.title,
                },
                "types": ["Cloud Misconfiguration"],
            },
            "resources": [resource],
            "cloud": {
                "provider": "AWS",
            },
            "unmapped": {
                "scanner_check_id": finding.check_id,
                "service": finding.service,
                "region": finding.region,
                "account_id": finding.account_id,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "source_type": finding.source_type,
                "source_id": finding.source_id,
                "source_product": finding.source_product,
                "first_observed_at": finding.first_observed_at,
                "last_observed_at": finding.last_observed_at,
                "risk_score": finding.risk_score,
                "risk_score_version": finding.risk_score_version,
                "source_file": finding.source_file,
                "source_address": finding.source_address,
            },
        }
        if finding.region:
            event["cloud"]["region"] = finding.region
        if finding.account_id:
            event["cloud"]["account"] = {"uid": finding.account_id}
        events.append(event)
    return events


def write_ocsf_report(findings: list[Finding], output_path: str | Path) -> None:
    """Write a JSON array of OCSF Detection Finding events."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    events = build_ocsf_report(findings)
    path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
