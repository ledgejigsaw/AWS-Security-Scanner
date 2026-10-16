from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from aws_security_scanner.integrations.inspector import inspector_to_finding
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.aws import AWSProvider


def item(**overrides):
    finding = {
        "findingArn": "arn:aws:inspector2:eu-west-2:123456789012:finding/f-123",
        "awsAccountId": "123456789012",
        "region": "eu-west-2",
        "type": "PACKAGE_VULNERABILITY",
        "status": "ACTIVE",
        "severity": "HIGH",
        "title": "Example vulnerable package",
        "description": "A package with a known vulnerability was detected.",
        "firstObservedAt": datetime(2026, 10, 1, tzinfo=timezone.utc),
        "lastObservedAt": datetime(2026, 10, 2, tzinfo=timezone.utc),
        "resources": [{"id": "i-0123456789abcdef0", "type": "AWS_EC2_INSTANCE"}],
    }
    finding.update(overrides)
    return finding


def test_inspector_mapping_preserves_identity_and_timestamps():
    finding = inspector_to_finding(item())
    assert finding is not None
    assert finding.check_id == "AWS-INSPECTOR-NATIVE"
    assert finding.severity is Severity.HIGH
    assert finding.source_type == "inspector"
    assert finding.source_id.endswith("finding/f-123")
    assert finding.account_id == "123456789012"
    assert finding.region == "eu-west-2"
    assert finding.resource == "i-0123456789abcdef0"
    assert finding.first_observed_at == "2026-10-01T00:00:00+00:00"
    assert finding.last_observed_at == "2026-10-02T00:00:00+00:00"


@pytest.mark.parametrize(("severity", "expected"), [
    ("CRITICAL", Severity.CRITICAL),
    ("HIGH", Severity.HIGH),
    ("MEDIUM", Severity.MEDIUM),
    ("LOW", Severity.LOW),
    ("INFORMATIONAL", Severity.INFO),
    ("UNTRIAGED", Severity.INFO),
    ("UNKNOWN", Severity.INFO),
    (None, Severity.INFO),
])
def test_inspector_severity_mapping_is_conservative(severity, expected):
    finding = inspector_to_finding(item(severity=severity))
    assert finding is not None
    assert finding.severity is expected


def test_inspector_mapper_ignores_missing_arn_and_non_active_findings():
    assert inspector_to_finding(item(findingArn="")) is None
    assert inspector_to_finding(item(status="CLOSED")) is None


def test_inspector_provider_paginates_deduplicates_and_obeys_limit():
    provider = AWSProvider.__new__(AWSProvider)
    provider.inspector2_client = Mock()
    provider.inspector2_client.list_findings.side_effect = [
        {"findings": [item(), item()], "nextToken": "page-2"},
        {"findings": [item(findingArn="arn:second")], "nextToken": "page-3"},
    ]
    results = provider.get_inspector_findings(limit=2)
    assert [result["findingArn"] for result in results] == [
        item()["findingArn"], "arn:second"
    ]
    assert provider.inspector2_client.list_findings.call_count == 2
    assert provider.inspector2_client.list_findings.call_args_list[0].kwargs["filterCriteria"] == {
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]
    }


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5])
def test_inspector_provider_rejects_invalid_limit(limit):
    provider = AWSProvider.__new__(AWSProvider)
    provider.inspector2_client = Mock()
    with pytest.raises(ValueError, match="between 1 and 1000"):
        provider.get_inspector_findings(limit=limit)
    provider.inspector2_client.list_findings.assert_not_called()


def test_inspector_provider_rejects_repeated_pagination_token():
    provider = AWSProvider.__new__(AWSProvider)
    provider.inspector2_client = Mock()
    provider.inspector2_client.list_findings.side_effect = [
        {"findings": [item()], "nextToken": "same"},
        {"findings": [item(findingArn="arn:second")], "nextToken": "same"},
    ]
    with pytest.raises(RuntimeError, match="repeated nextToken"):
        provider.get_inspector_findings(limit=10)
