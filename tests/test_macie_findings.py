from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from aws_security_scanner.integrations.macie import macie_to_finding
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.aws import AWSProvider


def item(**overrides):
    finding = {
        "id": "macie-finding-123",
        "accountId": "123456789012",
        "region": "eu-west-2",
        "archived": False,
        "title": "Sensitive data discovered",
        "description": "Macie identified sensitive data in an S3 object.",
        "severity": {"description": "High"},
        "resourcesAffected": {
            "s3Object": {"path": "s3://example-bucket/private.csv"},
            "s3Bucket": "example-bucket",
        },
        "createdAt": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "updatedAt": datetime(2026, 10, 2, tzinfo=timezone.utc),
    }
    finding.update(overrides)
    return finding


def test_macie_mapping_preserves_identity_and_timestamps_without_raw_payload():
    finding = macie_to_finding(item())
    assert finding is not None
    assert finding.check_id == "AWS-MACIE-NATIVE"
    assert finding.severity is Severity.HIGH
    assert finding.source_type == "macie"
    assert finding.source_id == "macie-finding-123"
    assert finding.account_id == "123456789012"
    assert finding.region == "eu-west-2"
    assert finding.resource == "s3://example-bucket/private.csv"
    assert finding.first_observed_at == "2026-10-01T00:00:00+00:00"
    assert finding.last_observed_at == "2026-10-02T00:00:00+00:00"
    assert "sample" not in (finding.evidence or "").lower()


@pytest.mark.parametrize(("label", "expected"), [
    ("Critical", Severity.CRITICAL),
    ("High", Severity.HIGH),
    ("Medium", Severity.MEDIUM),
    ("Low", Severity.LOW),
    ("Informational", Severity.INFO),
    ("unknown", Severity.INFO),
    (None, Severity.INFO),
])
def test_macie_severity_mapping_is_conservative(label, expected):
    finding = macie_to_finding(item(severity={"description": label}))
    assert finding is not None
    assert finding.severity is expected


def test_macie_mapper_ignores_missing_ids_and_archived_findings():
    assert macie_to_finding(item(id="")) is None
    assert macie_to_finding(item(archived=True)) is None


def test_macie_provider_paginates_deduplicates_and_obeys_limit():
    provider = AWSProvider.__new__(AWSProvider)
    provider.macie_client = Mock()
    provider.macie_client.list_findings.side_effect = [
        {"findingIds": ["one", "one"], "nextToken": "page-2"},
        {"findingIds": ["two"], "nextToken": None},
    ]
    provider.macie_client.get_findings.side_effect = [
        {"findings": [item(id="one")]},
        {"findings": [item(id="two")]},
    ]
    results = provider.get_macie_findings(limit=2)
    assert [result["id"] for result in results] == ["one", "two"]
    assert provider.macie_client.list_findings.call_count == 2
    assert provider.macie_client.get_findings.call_count == 2


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5])
def test_macie_provider_rejects_invalid_limit(limit):
    provider = AWSProvider.__new__(AWSProvider)
    provider.macie_client = Mock()
    with pytest.raises(ValueError, match="between 1 and 1000"):
        provider.get_macie_findings(limit=limit)
    provider.macie_client.list_findings.assert_not_called()


def test_macie_provider_rejects_repeated_pagination_token():
    provider = AWSProvider.__new__(AWSProvider)
    provider.macie_client = Mock()
    provider.macie_client.list_findings.side_effect = [
        {"findingIds": ["one"], "nextToken": "same"},
        {"findingIds": ["two"], "nextToken": "same"},
    ]
    provider.macie_client.get_findings.return_value = {"findings": [item()]}
    with pytest.raises(RuntimeError, match="repeated nextToken"):
        provider.get_macie_findings(limit=10)
