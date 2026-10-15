from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.security_services_rules import (
    check_guardduty_disabled,
    check_security_hub_disabled,
    check_macie_disabled,
)


def client_error(code, operation):
    return ClientError(
        {"Error": {"Code": code, "Message": code}},
        operation,
    )


def test_security_hub_enabled_returns_regional_resource():
    client = Mock()
    client.describe_hub.return_value = {
        "HubArn": "arn:aws:securityhub:eu-west-2:123456789012:hub/default",
        "SubscribedAt": "2026-10-01T00:00:00Z",
        "AutoEnableControls": True,
    }
    provider = AWSProvider(securityhub_client=client, region="eu-west-2")

    resources = provider.discover_security_hub()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_securityhub_hub"
    assert resources[0].attributes["enabled"] is True
    assert resources[0].region == "eu-west-2"


def test_security_hub_not_found_is_reported_as_disabled():
    client = Mock()
    client.describe_hub.side_effect = client_error(
        "ResourceNotFoundException", "DescribeHub"
    )
    provider = AWSProvider(securityhub_client=client, region="eu-west-2")

    resources = provider.discover_security_hub()

    assert resources[0].attributes["enabled"] is False
    assert len(check_security_hub_disabled(resources[0])) == 1


def test_security_hub_access_denied_is_not_misreported_as_disabled():
    client = Mock()
    client.describe_hub.side_effect = client_error(
        "AccessDeniedException", "DescribeHub"
    )
    provider = AWSProvider(securityhub_client=client)

    with pytest.raises(ClientError):
        provider.discover_security_hub()


def test_guardduty_without_detector_is_reported_as_disabled():
    client = Mock()
    client.list_detectors.return_value = {"DetectorIds": []}
    provider = AWSProvider(guardduty_client=client, region="eu-west-2")

    resources = provider.discover_guardduty()

    assert resources[0].attributes["enabled"] is False
    assert resources[0].region == "eu-west-2"
    assert len(check_guardduty_disabled(resources[0])) == 1


def test_guardduty_enabled_detector_is_not_flagged():
    client = Mock()
    client.list_detectors.return_value = {"DetectorIds": ["detector-123"]}
    client.get_detector.return_value = {
        "Status": "ENABLED",
        "FindingPublishingFrequency": "FIFTEEN_MINUTES",
        "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty",
    }
    provider = AWSProvider(guardduty_client=client, region="eu-west-2")

    resources = provider.discover_guardduty()

    assert resources[0].attributes["enabled"] is True
    assert check_guardduty_disabled(resources[0]) == []


def test_unknown_guardduty_state_is_not_treated_as_disabled():
    resource = Resource(
        resource_type="aws_guardduty_detector",
        resource_id="detector-unknown",
        attributes={"enabled": None, "status": None},
        source="aws",
        region="eu-west-2",
    )

    assert check_guardduty_disabled(resource) == []



def test_macie_enabled_session_is_discovered_regionally():
    client = Mock()
    client.get_macie_session.return_value = {
        "status": "ENABLED",
        "findingPublishingFrequency": "FIFTEEN_MINUTES",
        "createdAt": "2026-10-01T00:00:00Z",
    }
    provider = AWSProvider(macie_client=client, region="eu-west-2")

    resources = provider.discover_macie_session()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_macie_session"
    assert resources[0].attributes["enabled"] is True
    assert resources[0].attributes["status"] == "ENABLED"
    assert resources[0].region == "eu-west-2"
    assert check_macie_disabled(resources[0]) == []
    client.get_macie_session.assert_called_once_with()


def test_macie_not_found_and_paused_session_are_reported_as_disabled():
    client = Mock()
    client.get_macie_session.side_effect = client_error(
        "ResourceNotFoundException", "GetMacieSession"
    )
    provider = AWSProvider(macie_client=client, region="eu-west-2")

    resource = provider.discover_macie_session()[0]
    assert resource.attributes == {"enabled": False, "status": "NOT_ENABLED"}
    findings = check_macie_disabled(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "MACIE-001"
    assert findings[0].severity.value == "MEDIUM"

    client.get_macie_session.side_effect = None
    client.get_macie_session.return_value = {"status": "PAUSED"}
    paused = provider.discover_macie_session()[0]
    assert paused.attributes["enabled"] is False
    assert len(check_macie_disabled(paused)) == 1


def test_macie_access_denied_propagates_and_unknown_status_is_not_flagged():
    client = Mock()
    client.get_macie_session.side_effect = client_error(
        "AccessDeniedException", "GetMacieSession"
    )
    provider = AWSProvider(macie_client=client, region="eu-west-2")

    with pytest.raises(ClientError):
        provider.discover_macie_session()

    client.get_macie_session.side_effect = None
    client.get_macie_session.return_value = {"status": "UNKNOWN_STATUS"}
    unknown = provider.discover_macie_session()[0]
    assert unknown.attributes["enabled"] is None
    assert check_macie_disabled(unknown) == []
