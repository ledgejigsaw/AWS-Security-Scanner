import json

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.sarif_reporter import (
    build_sarif_report,
    write_sarif_report,
)


def make_finding(
    severity: Severity = Severity.HIGH,
    check_id: str = "S3-006",
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        service="S3",
        resource="company-data",
        title="Wildcard bucket policy",
        description="The policy allows a wildcard principal.",
        remediation="Restrict the principal.",
        region="eu-west-2",
        evidence="Principal=*",
    )


def test_sarif_report_has_version_rules_and_results():
    report = build_sarif_report([
        make_finding(),
        make_finding(Severity.CRITICAL, "S3-010"),
        make_finding(Severity.INFO, "IAM-006"),
    ])

    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["properties"]["scannerReportSchemaVersion"] == "1.0.0"
    assert run["tool"]["driver"]["name"] == "AWS Security Scanner"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "S3-006", "S3-010", "IAM-006"
    }
    assert [result["level"] for result in run["results"]] == [
        "error", "error", "note"
    ]
    assert run["results"][0]["properties"]["resource"] == "company-data"
    assert run["results"][0]["properties"]["evidence"] == "Principal=*"


def test_sarif_report_handles_empty_findings():
    report = build_sarif_report([])

    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["tool"]["driver"]["rules"] == []


def test_write_sarif_report_writes_valid_json(tmp_path):
    output_path = tmp_path / "reports" / "scan.sarif"

    write_sarif_report([make_finding()], output_path)

    assert output_path.exists()
    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["runs"][0]["results"][0]["ruleId"] == "S3-006"
