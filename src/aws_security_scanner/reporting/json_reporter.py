import json
from pathlib import Path

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.reporting.summary import build_summary


def build_json_report(findings: list[Finding]) -> dict:
    """Build a JSON-serialisable security scan report."""

    summary = build_summary(findings)

    return {
        "summary": {
            "total_findings": summary.total_findings,
            "by_severity": summary.by_severity,
        },
        "findings": [
            {
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
            for finding in findings
        ],
    }


def write_json_report(
    findings: list[Finding],
    output_path: str | Path,
) -> None:
    """Write a security scan report to a JSON file."""

    report = build_json_report(findings)
    output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")