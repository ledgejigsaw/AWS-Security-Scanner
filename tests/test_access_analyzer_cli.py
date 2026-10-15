from unittest.mock import patch

from aws_security_scanner.cli import run_scan
from aws_security_scanner.integrations.access_analyzer import access_analyzer_to_finding
from aws_security_scanner.reporting.json_reporter import build_json_report


def analyzer_item(**overrides):
    item = {
        "id": "aa-finding-1",
        "resource": "arn:aws:s3:::example-bucket",
        "resourceType": "AWS::S3::Bucket",
        "status": "ACTIVE",
        "isPublic": True,
        "findingType": "ExternalAccess",
        "resourceOwnerAccount": "123456789012",
        "region": "eu-west-2",
        "analyzerArn": "arn:aws:access-analyzer:eu-west-2:123456789012:analyzer/external",
        "createdAt": "2026-10-01T12:00:00Z",
        "updatedAt": "2026-10-02T12:00:00Z",
    }
    item.update(overrides)
    return item


def test_access_analyzer_provenance_is_exposed_in_json_report():
    finding = access_analyzer_to_finding(analyzer_item())
    assert finding is not None

    result = build_json_report([finding])["findings"][0]

    assert result["source_type"] == "access_analyzer"
    assert result["source_id"] == "aa-finding-1"
    assert result["source_product"].endswith(":analyzer/external")
    assert result["first_observed_at"] == "2026-10-01T12:00:00Z"


def test_native_finding_option_imports_access_analyzer_findings():
    with (
        patch("aws_security_scanner.cli.AWSProvider") as provider_cls,
        patch("aws_security_scanner.cli.RuleEngine") as engine_cls,
    ):
        provider = provider_cls.return_value
        provider.discover_s3_buckets.return_value = []
        provider.get_securityhub_findings.return_value = []
        provider.get_guardduty_findings.return_value = []
        provider.get_access_analyzer_findings.return_value = [analyzer_item()]
        engine_cls.return_value.scan.return_value = []

        findings = run_scan(
            "aws",
            region="eu-west-2",
            include_native_findings=True,
            services=["s3"],
        )

    native = [finding for finding in findings if finding.source_type == "access_analyzer"]
    assert len(native) == 1
    assert native[0].source_id == "aa-finding-1"
    provider.get_access_analyzer_findings.assert_called_once_with(limit=100)
