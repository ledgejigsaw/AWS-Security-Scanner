from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.scan_summary import build_scan_summary, scan_exit_code, threshold_is_met


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


def test_cli_accepts_summary_output_and_failure_threshold():
    from aws_security_scanner.cli import build_parser

    args = build_parser().parse_args([
        "--source", "terraform",
        "--file", "tests/fixtures/terraform/realistic_s3.json",
        "--summary-output", "reports/summary.json",
        "--fail-on", "HIGH",
    ])
    assert str(args.summary_output) == "reports/summary.json"
    assert args.fail_on == "HIGH"


def test_exit_code_contract_prioritises_incomplete_assessment():
    assert scan_exit_code(incomplete=False, threshold_met=False) == 0
    assert scan_exit_code(incomplete=True, threshold_met=False) == 1
    assert scan_exit_code(incomplete=True, threshold_met=True) == 1
    assert scan_exit_code(incomplete=False, threshold_met=True) == 3


def test_argparse_invalid_threshold_uses_usage_error_exit_code():
    import pytest
    from aws_security_scanner.cli import build_parser

    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(["--source", "terraform", "--fail-on", "URGENT"])
    assert error.value.code == 2


def test_hcl_diagnostics_mark_summary_incomplete_and_are_counted_by_code():
    diagnostics = [
        Finding(
            check_id="IAC-HCL-001",
            severity=Severity.INFO,
            service="Terraform HCL",
            resource="aws_s3_bucket.data",
            title="Unresolved expression",
            description="A variable was not resolved.",
            remediation="Supply supported inputs or use a reviewed plan.",
        ),
        Finding(
            check_id="IAC-HCL-002",
            severity=Severity.INFO,
            service="Terraform HCL",
            resource="module.network",
            title="Module was not expanded",
            description="The module was not analysed.",
            remediation="Review module source and scan boundaries.",
        ),
        finding("HIGH"),
    ]
    summary = build_scan_summary(
        diagnostics,
        source="hcl",
        region=None,
        services=None,
        report_format="json",
        report_path="reports/hcl.json",
        duration_seconds=0.1,
    )

    assert summary["status"] == "incomplete"
    assert summary["analysis"] == {
        "status": "incomplete",
        "diagnostics_total": 2,
        "diagnostics_by_code": {"IAC-HCL-001": 1, "IAC-HCL-002": 1},
        "unresolved_expressions": 1,
        "unexpanded_modules": 1,
        "unevaluated_data_sources": 0,
    }


def test_hcl_without_static_analysis_diagnostics_is_complete():
    summary = build_scan_summary(
        [finding("HIGH")],
        source="hcl",
        region=None,
        services=None,
        report_format="json",
        report_path="reports/hcl.json",
        duration_seconds=0.1,
    )
    assert summary["status"] == "complete"
    assert summary["analysis"]["status"] == "complete"
    assert summary["analysis"]["diagnostics_total"] == 0
