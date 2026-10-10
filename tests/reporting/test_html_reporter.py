from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.html_reporter import (
    build_html_report,
    write_html_report,
)


def make_finding() -> Finding:
    return Finding(
        check_id="S3-006",
        severity=Severity.HIGH,
        service="S3",
        resource="<bucket&name>",
        title="Wildcard policy",
        description="Policy contains <script>alert('x')</script>",
        remediation="Restrict the principal & resource.",
        region="eu-west-2",
        evidence="Principal=*",
    )


def test_html_report_contains_summary_and_finding_details():
    report = build_html_report([make_finding()])

    assert "Total findings: <strong>1</strong>" in report
    assert "S3-006" in report
    assert "Wildcard policy" in report
    assert "&lt;script&gt;" in report
    assert "<script>alert('x')</script>" not in report
    assert "&lt;bucket&amp;name&gt;" in report


def test_html_report_handles_no_findings():
    report = build_html_report([])

    assert "Total findings: <strong>0</strong>" in report
    assert "No findings." in report


def test_write_html_report_creates_parent_directory(tmp_path):
    output_path = tmp_path / "nested" / "scan.html"

    write_html_report([make_finding()], output_path)

    assert output_path.exists()
    assert "AWS Security Scanner Report" in output_path.read_text(encoding="utf-8")
