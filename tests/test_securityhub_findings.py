import json
from unittest.mock import Mock

import pytest

from aws_security_scanner.baseline_history import (
    diff_findings,
    finding_fingerprint,
    load_baseline_records,
    write_baseline,
)
from aws_security_scanner.cli import build_parser
from aws_security_scanner.integrations.securityhub import securityhub_to_finding
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.reporting.html_reporter import build_html_report
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report


def securityhub_item(**overrides):
    item = {
        "Id": "arn:aws:securityhub:eu-west-2:123456789012:subscription/test/finding-1",
        "ProductArn": "arn:aws:securityhub:eu-west-2::product/aws/guardduty",
        "ProductName": "GuardDuty",
        "AwsAccountId": "123456789012",
        "Region": "eu-west-2",
        "Title": "Suspicious activity",
        "Description": "A test finding",
        "Severity": {"Label": "HIGH"},
        "Resources": [{"Id": "arn:aws:ec2:eu-west-2:123456789012:instance/i-123"}],
        "FirstObservedAt": "2026-10-01T12:00:00Z",
        "LastObservedAt": "2026-10-02T12:00:00Z",
        "Remediation": {"Recommendation": {"Text": "Investigate the instance."}},
    }
    item.update(overrides)
    return item


def test_securityhub_mapping_preserves_source_identity_and_timestamps():
    finding = securityhub_to_finding(securityhub_item())

    assert finding is not None
    assert finding.check_id == "AWS-SHUB-NATIVE"
    assert finding.severity is Severity.HIGH
    assert finding.source_type == "security_hub"
    assert finding.source_id == securityhub_item()["Id"]
    assert finding.source_product == securityhub_item()["ProductArn"]
    assert finding.first_observed_at == "2026-10-01T12:00:00Z"
    assert finding.last_observed_at == "2026-10-02T12:00:00Z"
    assert finding.account_id == "123456789012"
    assert finding.resource.endswith("instance/i-123")


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFORMATIONAL", Severity.INFO),
        ("unexpected", Severity.INFO),
    ],
)
def test_securityhub_severity_mapping_is_conservative(label, expected):
    finding = securityhub_to_finding(securityhub_item(Severity={"Label": label}))
    assert finding is not None
    assert finding.severity is expected


def test_securityhub_mapping_rejects_item_without_stable_source_id():
    assert securityhub_to_finding(securityhub_item(Id="")) is None


def test_securityhub_provider_paginates_deduplicates_and_obeys_limit():
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    first = securityhub_item()
    duplicate = securityhub_item()
    second = securityhub_item(
        Id="finding-2",
        Title="Second finding",
    )
    provider.securityhub_client.get_findings.side_effect = [
        {"Findings": [first, duplicate], "NextToken": "page-2"},
        {"Findings": [second], "NextToken": "page-3"},
    ]

    findings = provider.get_securityhub_findings(limit=2)

    assert [item["Title"] for item in findings] == ["Suspicious activity", "Second finding"]
    assert provider.securityhub_client.get_findings.call_count == 2
    assert provider.securityhub_client.get_findings.call_args_list[0].kwargs == {
        "MaxResults": 2,
        "Filters": {"RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}]},
    }
    assert provider.securityhub_client.get_findings.call_args_list[1].kwargs == {
        "MaxResults": 1,
        "Filters": {"RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}]},
        "NextToken": "page-2",
    }


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5])
def test_securityhub_provider_rejects_invalid_limit(limit):
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    with pytest.raises(ValueError, match="between 1 and 1000"):
        provider.get_securityhub_findings(limit=limit)
    provider.securityhub_client.get_findings.assert_not_called()


def test_native_finding_fingerprints_do_not_collapse_on_same_resource():
    first = securityhub_to_finding(securityhub_item(Id="native-1"))
    second = securityhub_to_finding(securityhub_item(Id="native-2"))
    assert first is not None and second is not None
    assert first.resource == second.resource
    assert finding_fingerprint(first) != finding_fingerprint(second)


def test_native_provenance_is_exposed_in_all_report_formats():
    finding = securityhub_to_finding(securityhub_item())
    assert finding is not None

    json_finding = build_json_report([finding])["findings"][0]
    assert json_finding["source_type"] == "security_hub"
    assert json_finding["source_id"] == finding.source_id
    assert json_finding["first_observed_at"] == finding.first_observed_at

    html = build_html_report([finding])
    assert "Source finding ID" in html
    assert finding.source_id in html
    assert "First observed" in html

    sarif_result = build_sarif_report([finding])["runs"][0]["results"][0]
    assert sarif_result["properties"]["sourceType"] == "security_hub"
    assert sarif_result["properties"]["sourceId"] == finding.source_id
    assert sarif_result["properties"]["lastObservedAt"] == finding.last_observed_at


def test_scanner_finding_keeps_legacy_baseline_fingerprint_and_report_shape():
    finding = Finding(
        check_id="S3-001",
        severity=Severity.CRITICAL,
        service="S3",
        resource="bucket-example",
        title="Public bucket",
        description="Example",
        remediation="Block public access",
    )
    assert len(finding_fingerprint(finding)) == 64
    report_finding = build_json_report([finding])["findings"][0]
    assert "source_type" not in report_finding
    assert "source_id" not in report_finding


def test_cli_accepts_opt_in_native_findings_and_limit():
    args = build_parser().parse_args([
        "--source", "aws",
        "--region", "eu-west-2",
        "--include-native-findings",
        "--native-findings-limit", "250",
    ])
    assert args.include_native_findings is True
    assert args.native_findings_limit == 250


def test_native_finding_source_metadata_survives_baseline_and_diff(tmp_path):
    finding = securityhub_to_finding(securityhub_item())
    assert finding is not None
    path = tmp_path / "native-baseline.json"

    write_baseline([finding], path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    entry = payload["findings"][0]
    assert entry["source_type"] == "security_hub"
    assert entry["source_id"] == finding.source_id
    assert entry["first_observed_at"] == finding.first_observed_at
    assert entry["last_observed_at"] == finding.last_observed_at

    records = load_baseline_records(path)
    unchanged = diff_findings([finding], records)["unchanged"][0]
    assert unchanged["source_id"] == finding.source_id
    assert unchanged["first_observed_at"] == finding.first_observed_at
    assert unchanged["last_observed_at"] == finding.last_observed_at

    resolved = diff_findings([], records)["resolved"][0]
    assert resolved["source_id"] == finding.source_id
    assert resolved["first_observed_at"] == finding.first_observed_at
    assert resolved["last_observed_at"] == finding.last_observed_at



def test_securityhub_provider_filters_workflow_record_and_compliance_status():
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    provider.securityhub_client.get_findings.return_value = {"Findings": []}

    assert provider.get_securityhub_findings(
        limit=10,
        workflow_statuses=["NEW", "NOTIFIED"],
        record_state="ARCHIVED",
        compliance_status="FAILED",
    ) == []

    assert provider.securityhub_client.get_findings.call_args.kwargs == {
        "MaxResults": 10,
        "Filters": {
            "RecordState": [{"Comparison": "EQUALS", "Value": "ARCHIVED"}],
            "WorkflowStatus": [
                {"Comparison": "EQUALS", "Value": "NEW"},
                {"Comparison": "EQUALS", "Value": "NOTIFIED"},
            ],
            "ComplianceStatus": [{"Comparison": "EQUALS", "Value": "FAILED"}],
        },
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"workflow_statuses": ["INVALID"]},
        {"workflow_statuses": []},
        {"record_state": "UNKNOWN"},
        {"compliance_status": "MAYBE"},
    ],
)
def test_securityhub_provider_rejects_invalid_filters(kwargs):
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    with pytest.raises(ValueError):
        provider.get_securityhub_findings(**kwargs)
    provider.securityhub_client.get_findings.assert_not_called()


def test_securityhub_mapping_preserves_control_and_workflow_context():
    finding = securityhub_to_finding(securityhub_item(
        GeneratorId="aws-foundational-security-best-practices/v/1.0.0/EC2.1",
        Compliance={"Status": "FAILED"},
        Workflow={"Status": "NEW"},
        RecordState="ACTIVE",
    ))
    assert finding is not None
    assert "EC2.1" in finding.evidence
    assert "compliance status: FAILED" in finding.evidence
    assert "workflow status: NEW" in finding.evidence
    assert "record state: ACTIVE" in finding.evidence


def test_cli_accepts_securityhub_control_filters():
    args = build_parser().parse_args([
        "--source", "aws",
        "--include-native-findings",
        "--securityhub-workflow-status", "NEW",
        "--securityhub-workflow-status", "NOTIFIED",
        "--securityhub-record-state", "ARCHIVED",
        "--securityhub-compliance-status", "FAILED",
    ])
    assert args.securityhub_workflow_status == ["NEW", "NOTIFIED"]
    assert args.securityhub_record_state == "ARCHIVED"
    assert args.securityhub_compliance_status == "FAILED"
