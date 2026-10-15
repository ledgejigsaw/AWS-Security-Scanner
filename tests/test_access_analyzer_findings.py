from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from aws_security_scanner.integrations.access_analyzer import access_analyzer_to_finding
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.aws import AWSProvider


def item(**overrides):
    finding = {
        "id": "finding-123",
        "resource": "arn:aws:s3:::customer-data",
        "resourceType": "AWS::S3::Bucket",
        "status": "ACTIVE",
        "isPublic": True,
        "findingType": "ExternalAccess",
        "resourceOwnerAccount": "123456789012",
        "region": "eu-west-2",
        "analyzerArn": "arn:aws:access-analyzer:eu-west-2:123456789012:analyzer/external",
        "createdAt": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "updatedAt": datetime(2026, 10, 2, tzinfo=timezone.utc),
        # Deliberately ensure detailed policy/principal data is not needed by the mapper.
        "principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
    }
    finding.update(overrides)
    return finding


def test_access_analyzer_mapping_preserves_provenance_without_raw_policy_data():
    finding = access_analyzer_to_finding(item())

    assert finding is not None
    assert finding.check_id == "AWS-AA-NATIVE"
    assert finding.severity is Severity.HIGH
    assert finding.source_type == "access_analyzer"
    assert finding.source_id == "finding-123"
    assert finding.source_product.endswith(":analyzer/external")
    assert finding.account_id == "123456789012"
    assert finding.region == "eu-west-2"
    assert finding.first_observed_at == "2026-10-01T00:00:00+00:00"
    assert finding.last_observed_at == "2026-10-02T00:00:00+00:00"
    assert "condition" not in (finding.evidence or "")
    assert "principal" not in (finding.evidence or "")


@pytest.mark.parametrize(
    ("finding_type", "is_public", "expected"),
    [
        ("ExternalAccess", True, Severity.HIGH),
        ("ExternalAccess", False, Severity.MEDIUM),
        ("UnusedAccess", False, Severity.LOW),
        ("UnexpectedType", None, Severity.INFO),
    ],
)
def test_access_analyzer_severity_mapping_is_conservative(finding_type, is_public, expected):
    finding = access_analyzer_to_finding(item(findingType=finding_type, isPublic=is_public))
    assert finding is not None
    assert finding.severity is expected


def test_access_analyzer_mapping_rejects_missing_id_and_non_active_findings():
    assert access_analyzer_to_finding(item(id="")) is None
    assert access_analyzer_to_finding(item(status="ARCHIVED")) is None


def test_access_analyzer_provider_paginates_deduplicates_and_obeys_limit():
    provider = AWSProvider.__new__(AWSProvider)
    provider.accessanalyzer_client = Mock()
    provider.accessanalyzer_client.list_analyzers.side_effect = [
        {"analyzers": [{"arn": "analyzer-1"}], "nextToken": "analyzer-page-2"},
        {"analyzers": [{"arn": "analyzer-2"}]},
    ]
    provider.accessanalyzer_client.list_findings_v2.side_effect = [
        {"findings": [item(), item()], "nextToken": "findings-page-2"},
        {"findings": [item(id="finding-2", isPublic=False)]},
    ]

    findings = provider.get_access_analyzer_findings(limit=2)

    assert [finding["id"] for finding in findings] == ["finding-123", "finding-2"]
    assert provider.accessanalyzer_client.list_analyzers.call_count == 2
    assert provider.accessanalyzer_client.list_findings_v2.call_count == 2
    first = provider.accessanalyzer_client.list_findings_v2.call_args_list[0].kwargs
    assert first["analyzerArn"] == "analyzer-1"
    assert first["filter"] == {"status": [{"eq": ["ACTIVE"]}]}
    assert first["maxResults"] == 2


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5])
def test_access_analyzer_provider_rejects_invalid_limit(limit):
    provider = AWSProvider.__new__(AWSProvider)
    provider.accessanalyzer_client = Mock()

    with pytest.raises(ValueError, match="between 1 and 1000"):
        provider.get_access_analyzer_findings(limit=limit)

    provider.accessanalyzer_client.list_analyzers.assert_not_called()


def test_access_analyzer_permission_errors_propagate():
    provider = AWSProvider.__new__(AWSProvider)
    provider.accessanalyzer_client = Mock()
    provider.accessanalyzer_client.list_analyzers.side_effect = PermissionError("Access denied")

    with pytest.raises(PermissionError, match="Access denied"):
        provider.get_access_analyzer_findings()
