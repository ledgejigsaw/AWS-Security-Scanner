import json
from pathlib import Path

from aws_security_scanner.models.finding import Finding, Severity


SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def build_sarif_report(findings: list[Finding]) -> dict:
    """Build a SARIF 2.1.0 report suitable for code-scanning ingestion."""
    rules_by_id = {}

    for finding in findings:
        rules_by_id.setdefault(
            finding.check_id,
            {
                "id": finding.check_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": SARIF_LEVELS[finding.severity],
                },
                "help": {"text": finding.remediation},
            },
        )

    results = []
    for finding in findings:
        properties = {
            "service": finding.service,
            "resource": finding.resource,
            "region": finding.region,
            "severity": finding.severity.value,
            "remediation": finding.remediation,
        }
        if finding.evidence is not None:
            properties["evidence"] = finding.evidence

        results.append(
            {
                "ruleId": finding.check_id,
                "level": SARIF_LEVELS[finding.severity],
                "message": {
                    "text": f"{finding.title}: {finding.description}",
                },
                "properties": properties,
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWS Security Scanner",
                        "informationUri": "https://github.com/ledgejigsaw/AWS-Security-Scanner",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(
    findings: list[Finding],
    output_path: str | Path,
) -> None:
    """Write a SARIF 2.1.0 report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(build_sarif_report(findings), indent=2) + "\n",
        encoding="utf-8",
    )
