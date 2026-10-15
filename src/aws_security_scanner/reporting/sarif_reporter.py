import json
from pathlib import Path

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.compliance import framework_metadata, mappings_for_check


SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def build_sarif_report(
    findings: list[Finding],
    compliance_mapping: dict | None = None,
    assessment_metadata: dict | None = None,
) -> dict:
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
        if finding.account_id is not None:
            properties["accountId"] = finding.account_id
        if finding.risk_score is not None:
            properties["riskScore"] = finding.risk_score
            properties["riskScoreVersion"] = finding.risk_score_version
            properties["riskExplanation"] = finding.risk_explanation
        if finding.source_type != "scanner":
            properties["sourceType"] = finding.source_type
            properties["sourceId"] = finding.source_id
            properties["sourceProduct"] = finding.source_product
            properties["firstObservedAt"] = finding.first_observed_at
            properties["lastObservedAt"] = finding.last_observed_at
        if compliance_mapping is not None:
            properties["complianceMappings"] = mappings_for_check(
                compliance_mapping, finding.check_id
            )

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

    run = {
        "tool": {
            "driver": {
                "name": "AWS Security Scanner",
                "informationUri": "https://github.com/ledgejigsaw/AWS-Security-Scanner",
                "rules": list(rules_by_id.values()),
            }
        },
        "results": results,
    }
    run_properties = {}
    if assessment_metadata is not None:
        run_properties["assessment"] = assessment_metadata
    metadata = framework_metadata(compliance_mapping)
    if metadata is not None:
        run_properties["complianceFramework"] = metadata
    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif_report(
    findings: list[Finding],
    output_path: str | Path,
    compliance_mapping: dict | None = None,
    assessment_metadata: dict | None = None,
) -> None:
    """Write a SARIF 2.1.0 report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(build_sarif_report(findings, compliance_mapping, assessment_metadata), indent=2) + "\n",
        encoding="utf-8",
    )
