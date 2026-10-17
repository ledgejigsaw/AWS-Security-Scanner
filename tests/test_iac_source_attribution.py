import json

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider
from aws_security_scanner.reporting.html_reporter import build_html_report
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report


def test_hcl_source_file_and_address_flow_to_json_html_and_sarif(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        'resource "aws_s3_bucket" "example" {\n  bucket = "example-bucket"\n}\n',
        encoding="utf-8",
    )
    resources = TerraformHCLProvider(source).discover()
    assert len(resources) == 1
    resource = resources[0]
    assert resource.source_file == str(source)
    assert resource.source_address == "aws_s3_bucket.example"

    def rule(item):
        return [Finding(
            check_id="TEST-IAC-001",
            severity=Severity.HIGH,
            service="S3",
            resource=item.resource_id,
            title="Test finding",
            description="Test source attribution",
            remediation="Review configuration",
        )]

    rule.resource_type = "aws_s3_bucket"
    findings = RuleEngine([rule]).scan(resources)

    json_report = build_json_report(findings)
    item = json_report["findings"][0]
    assert item["source_file"] == str(source)
    assert item["source_address"] == "aws_s3_bucket.example"

    html_report = build_html_report(findings)
    assert "<th>Source file</th>" in html_report
    assert str(source) in html_report
    assert "aws_s3_bucket.example" in html_report

    sarif = build_sarif_report(findings)
    result = sarif["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == str(source)
    assert result["locations"][0]["logicalLocations"][0]["name"] == "aws_s3_bucket.example"


def test_findings_without_source_attribution_keep_existing_report_shape():
    finding = Finding(
        check_id="TEST-001",
        severity=Severity.INFO,
        service="Test",
        resource="example",
        title="Test",
        description="Test",
        remediation="Test",
    )
    assert "source_file" not in build_json_report([finding])["findings"][0]
    assert "locations" not in build_sarif_report([finding])["runs"][0]["results"][0]
