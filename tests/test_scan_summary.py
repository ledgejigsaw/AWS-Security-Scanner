from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.scan_summary import build_scan_summary, threshold_is_met


def finding(severity):
    return Finding(
        check_id="S3-001",
        severity=Severity(severity),
        service="S3",
        resource="example",
        title="Example finding",
        description="Test fixture",
        remediation="Review configuration",
    )


def test_failure_threshold_matches_equal_or_more_severe_findings():
    assert threshold_is_met([finding("CRITICAL")], "HIGH")
    assert threshold_is_met([finding("HIGH")], "HIGH")
    assert not threshold_is_met([finding("MEDIUM")], "HIGH")
    assert not threshold_is_met([finding("CRITICAL")], None)


def test_machine_summary_has_versioned_counts_and_incomplete_coverage():
    summary = build_scan_summary(
        [finding("HIGH"), finding("INFO")],
        source="aws",
        region="eu-west-2",
        services=["s3", "kms", "s3"],
        report_format="json",
        report_path="reports/scan.json",
        duration_seconds=1.23456789,
        discovery_coverage=[
            {"service": "s3", "status": "success"},
            {"service": "kms", "status": "failed"},
        ],
        fail_on="HIGH",
        threshold_met=True,
    )

    assert summary["schema_version"] == "1.0.0"
    assert summary["status"] == "incomplete"
    assert summary["scope"]["services"] == ["kms", "s3"]
    assert summary["findings"]["total"] == 2
    assert summary["findings"]["by_severity"]["HIGH"] == 1
    assert summary["findings"]["by_severity"]["INFO"] == 1
    assert summary["discovery"]["domains_with_gaps"] == 1
    assert summary["failure_threshold"] == {"severity": "HIGH", "met": True}


def test_machine_summary_marks_failed_multi_account_assessment_incomplete():
    summary = build_scan_summary(
        [],
        source="aws",
        region="eu-west-2",
        services=None,
        report_format="json",
        report_path="reports/scan.json",
        duration_seconds=0,
        assessment_metadata={
            "summary": {
                "total_accounts": 2,
                "successful_accounts": 1,
                "failed_accounts": 1,
            }
        },
    )
    assert summary["status"] == "incomplete"
    assert summary["accounts"] == {"total": 2, "successful": 1, "failed": 1}
