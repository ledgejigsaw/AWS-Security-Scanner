from unittest.mock import Mock

import pytest

from aws_security_scanner.cli import build_parser
from aws_security_scanner.integrations.guardduty import guardduty_to_finding
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.aws import AWSProvider


def guardduty_item(**overrides):
    item = {
        "Id": "gd-finding-1",
        "AccountId": "123456789012",
        "Region": "eu-west-2",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Title": "SSH brute force activity",
        "Description": "An instance received repeated SSH login attempts.",
        "Severity": 7.2,
        "CreatedAt": "2026-10-10T12:00:00Z",
        "UpdatedAt": "2026-10-11T12:00:00Z",
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {"InstanceId": "i-0123456789abcdef0"},
        },
    }
    item.update(overrides)
    return item


def test_guardduty_mapping_preserves_provenance_and_resource_identity():
    finding = guardduty_to_finding(guardduty_item(), fallback_region="us-east-1")

    assert finding is not None
    assert finding.check_id == "AWS-GD-NATIVE"
    assert finding.severity is Severity.HIGH
    assert finding.source_type == "guardduty"
    assert finding.source_id == "gd-finding-1"
    assert finding.source_product == "GuardDuty"
    assert finding.account_id == "123456789012"
    assert finding.region == "eu-west-2"
    assert finding.resource == "i-0123456789abcdef0"
    assert finding.first_observed_at == "2026-10-10T12:00:00Z"
    assert finding.last_observed_at == "2026-10-11T12:00:00Z"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (4.0, Severity.MEDIUM),
        (0.1, Severity.LOW),
        (0, Severity.INFO),
        ("high", Severity.INFO),
        (None, Severity.INFO),
        (True, Severity.INFO),
    ],
)
def test_guardduty_severity_mapping_is_conservative(value, expected):
    finding = guardduty_to_finding(guardduty_item(Severity=value))
    assert finding is not None
    assert finding.severity is expected


def test_guardduty_mapping_rejects_item_without_stable_source_id():
    assert guardduty_to_finding(guardduty_item(Id="")) is None


def test_guardduty_provider_paginates_deduplicates_and_obeys_limit():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    provider.guardduty_client.list_detectors.return_value = {
        "DetectorIds": ["detector-1"]
    }
    provider.guardduty_client.list_findings.side_effect = [
        {"FindingIds": ["id-1", "id-1"], "NextToken": "page-2"},
        {"FindingIds": ["id-2"], "NextToken": "page-3"},
    ]
    provider.guardduty_client.get_findings.return_value = {
        "Findings": [guardduty_item(Id="id-1"), guardduty_item(Id="id-2")]
    }

    findings = provider.get_guardduty_findings(limit=2)

    assert [item["Id"] for item in findings] == ["id-1", "id-2"]
    assert provider.guardduty_client.list_findings.call_count == 2
    assert provider.guardduty_client.list_findings.call_args_list[0].kwargs == {
        "DetectorId": "detector-1",
        "MaxResults": 2,
    }
    assert provider.guardduty_client.list_findings.call_args_list[1].kwargs == {
        "DetectorId": "detector-1",
        "MaxResults": 1,
        "NextToken": "page-2",
    }
    provider.guardduty_client.get_findings.assert_called_once_with(
        DetectorId="detector-1",
        FindingIds=["id-1", "id-2"],
    )


@pytest.mark.parametrize("limit", [0, -1, 1001, True, 1.5])
def test_guardduty_provider_rejects_invalid_limit(limit):
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    with pytest.raises(ValueError, match="between 1 and 1000"):
        provider.get_guardduty_findings(limit=limit)
    provider.guardduty_client.list_detectors.assert_not_called()


def test_native_findings_cli_help_mentions_both_sources():
    args = build_parser().parse_args([
        "--source", "aws",
        "--include-native-findings",
        "--native-findings-limit", "25",
    ])
    assert args.include_native_findings is True
    assert args.native_findings_limit == 25



def test_guardduty_provider_applies_archived_and_updated_after_filters():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    provider.guardduty_client.list_detectors.return_value = {"DetectorIds": ["detector-1"]}
    provider.guardduty_client.get_detector.return_value = {"Status": "ENABLED"}
    provider.guardduty_client.list_findings.return_value = {"FindingIds": []}

    assert provider.get_guardduty_findings(
        limit=10,
        archived=False,
        updated_after="2026-10-01T00:00:00Z",
        require_detector=True,
    ) == []

    assert provider.guardduty_client.list_findings.call_args.kwargs == {
        "DetectorId": "detector-1",
        "MaxResults": 10,
        "FindingCriteria": {
            "Criterion": {
                "service.archived": {"Eq": ["false"]},
                "updatedAt": {"Gte": ["2026-10-01T00:00:00Z"]},
            }
        },
    }


def test_guardduty_provider_marks_missing_detector_as_unavailable():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    provider.guardduty_client.list_detectors.return_value = {"DetectorIds": []}

    with pytest.raises(RuntimeError, match="GuardDuty is not enabled"):
        provider.get_guardduty_findings(require_detector=True)

    provider.guardduty_client.list_findings.assert_not_called()


def test_guardduty_provider_marks_disabled_detector_as_unavailable():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()
    provider.guardduty_client.list_detectors.return_value = {"DetectorIds": ["detector-1"]}
    provider.guardduty_client.get_detector.return_value = {"Status": "DISABLED"}

    with pytest.raises(RuntimeError, match="detector is not enabled"):
        provider.get_guardduty_findings(require_detector=True)

    provider.guardduty_client.list_findings.assert_not_called()


def test_guardduty_provider_rejects_timezone_missing_update_filter():
    provider = AWSProvider.__new__(AWSProvider)
    provider.guardduty_client = Mock()

    with pytest.raises(ValueError, match="include a timezone"):
        provider.get_guardduty_findings(updated_after="2026-10-01T00:00:00")

    provider.guardduty_client.list_detectors.assert_not_called()


def test_cli_accepts_guardduty_multi_region_and_filter_options():
    args = build_parser().parse_args([
        "--source", "aws",
        "--include-native-findings",
        "--guardduty-region", "eu-west-2",
        "--guardduty-region", "us-east-1",
        "--guardduty-record-state", "ACTIVE",
        "--guardduty-updated-after", "2026-10-01T00:00:00Z",
    ])
    assert args.guardduty_region == ["eu-west-2", "us-east-1"]
    assert args.guardduty_record_state == "ACTIVE"
    assert args.guardduty_updated_after == "2026-10-01T00:00:00Z"
