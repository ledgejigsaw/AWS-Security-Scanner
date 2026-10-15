import json
from pathlib import Path

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.reporting.summary import build_summary
from aws_security_scanner.compliance import framework_metadata, mappings_for_check


def build_json_report(
    findings: list[Finding],
    compliance_mapping: dict | None = None,
    assessment_metadata: dict | None = None,
) -> dict:
    """Build a JSON-serialisable security scan report."""

    summary = build_summary(findings)

    finding_items = []
    for finding in findings:
        item = {
            "check_id": finding.check_id,
            "severity": finding.severity.value,
            "service": finding.service,
            "resource": finding.resource,
            "title": finding.title,
            "description": finding.description,
            "remediation": finding.remediation,
            "region": finding.region,
            "evidence": finding.evidence,
        }
        if finding.account_id is not None:
            item["account_id"] = finding.account_id
        if finding.source_type != "scanner":
            item["source_type"] = finding.source_type
            item["source_id"] = finding.source_id
            item["source_product"] = finding.source_product
            item["first_observed_at"] = finding.first_observed_at
            item["last_observed_at"] = finding.last_observed_at
        finding_items.append(item)

    report = {
        "summary": {
            "total_findings": summary.total_findings,
            "by_severity": summary.by_severity,
        },
        "findings": finding_items,
    }
    if assessment_metadata is not None:
        report["assessment"] = assessment_metadata
    metadata = framework_metadata(compliance_mapping)
    if metadata is not None:
        report["compliance_framework"] = metadata
        for item in report["findings"]:
            item["compliance_mappings"] = mappings_for_check(
                compliance_mapping, item["check_id"]
            )
    return report


def write_json_report(
    findings: list[Finding],
    output_path: str | Path,
    compliance_mapping: dict | None = None,
    assessment_metadata: dict | None = None,
) -> None:
    """Write a security scan report to a JSON file."""

    report = build_json_report(findings, compliance_mapping, assessment_metadata)
    output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")