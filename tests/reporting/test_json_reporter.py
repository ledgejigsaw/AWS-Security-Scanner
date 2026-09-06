import json

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.json_reporter import (
    build_json_report,
    write_json_report,
)


def make_finding(
    severity: Severity,
    check_id: str = "TEST-001",
) -> Finding:
    """Create a test finding."""

    return Finding(
        check_id=check_id,
        severity=severity,
        service="S3",
        resource="test-bucket",
        title="Test finding",
        description="Test description",
        remediation="Test remediation",
        region="eu-west-2",
        evidence="Test evidence",
    )


def test_build_json_report_contains_summary():
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
    ]

    report = build_json_report(findings)

    assert report["summary"]["total_findings"] == 3

    assert report["summary"]["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }


def test_build_json_report_contains_findings():
    findings = [
        make_finding(
            Severity.HIGH,
            check_id="S3-006",
        )
    ]

    report = build_json_report(findings)

    assert len(report["findings"]) == 1

    finding = report["findings"][0]

    assert finding["check_id"] == "S3-006"
    assert finding["severity"] == "HIGH"
    assert finding["service"] == "S3"
    assert finding["resource"] == "test-bucket"
    assert finding["region"] == "eu-west-2"
    assert finding["evidence"] == "Test evidence"


def test_build_json_report_handles_no_findings():
    report = build_json_report([])

    assert report["summary"]["total_findings"] == 0
    assert report["findings"] == []


def test_write_json_report_creates_valid_json_file(tmp_path):
    findings = [
        make_finding(Severity.CRITICAL)
    ]

    output_path = tmp_path / "scan.json"

    write_json_report(findings, output_path)

    assert output_path.exists()

    with output_path.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["total_findings"] == 1
    assert report["findings"][0]["severity"] == "CRITICAL"