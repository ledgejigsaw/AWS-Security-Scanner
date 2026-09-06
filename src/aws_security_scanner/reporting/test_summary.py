from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.summary import build_summary


def make_finding(severity: Severity) -> Finding:
    """Create a test finding."""

    return Finding(
        check_id="TEST-001",
        severity=severity,
        service="S3",
        resource="test-bucket",
        title="Test finding",
        description="Test description",
        remediation="Test remediation",
    )


def test_empty_findings_produces_empty_summary():
    summary = build_summary([])

    assert summary.total_findings == 0
    assert summary.critical == 0
    assert summary.high == 0
    assert summary.medium == 0
    assert summary.low == 0
    assert summary.info == 0


def test_summary_counts_findings_by_severity():
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM),
        make_finding(Severity.LOW),
        make_finding(Severity.INFO),
    ]

    summary = build_summary(findings)

    assert summary.total_findings == 6
    assert summary.critical == 1
    assert summary.high == 2
    assert summary.medium == 1
    assert summary.low == 1
    assert summary.info == 1


def test_summary_exposes_counts_by_severity():
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
    ]

    summary = build_summary(findings)

    assert summary.by_severity == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }