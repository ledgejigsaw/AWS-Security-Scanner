from unittest.mock import Mock

import pytest

from aws_security_scanner.providers.aws import AWSProvider


def provider_with_config(response_recorders, response_channels, response_statuses=None):
    provider = AWSProvider.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.config_client = Mock()
    provider.config_client.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": response_recorders
    }
    provider.config_client.describe_delivery_channels.return_value = {
        "DeliveryChannels": response_channels
    }
    provider.config_client.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": response_statuses or []
    }
    return provider


def test_config_discovery_explicitly_reports_missing_recorder_and_channel():
    provider = provider_with_config([], [])

    [resource] = provider.discover_aws_config()

    assert resource.resource_type == "aws_config_service"
    assert resource.region == "eu-west-2"
    assert resource.attributes == {
        "recorder_configured": False,
        "recording": None,
        "delivery_channel_configured": False,
    }
    provider.config_client.describe_configuration_recorder_status.assert_not_called()


def test_config_discovery_reports_recording_and_channel_when_configured():
    provider = provider_with_config(
        [{"name": "default"}],
        [{"name": "default"}],
        [{"name": "default", "recording": True}],
    )

    [resource] = provider.discover_aws_config()

    assert resource.attributes == {
        "recorder_configured": True,
        "recording": True,
        "delivery_channel_configured": True,
    }
    provider.config_client.describe_configuration_recorder_status.assert_called_once_with(
        ConfigurationRecorderNames=["default"]
    )


def test_config_discovery_reports_stopped_if_any_recorder_is_stopped():
    provider = provider_with_config(
        [{"name": "one"}, {"name": "two"}],
        [{"name": "default"}],
        [
            {"name": "one", "recording": True},
            {"name": "two", "recording": False},
        ],
    )

    [resource] = provider.discover_aws_config()

    assert resource.attributes["recording"] is False


def test_config_discovery_keeps_missing_recorder_status_unknown():
    provider = provider_with_config(
        [{"name": "default"}],
        [{"name": "default"}],
        [],
    )

    [resource] = provider.discover_aws_config()

    assert resource.attributes["recorder_configured"] is True
    assert resource.attributes["recording"] is None


def test_config_discovery_propagates_permission_errors():
    provider = provider_with_config([], [])
    provider.config_client.describe_configuration_recorders.side_effect = PermissionError(
        "Access denied"
    )

    with pytest.raises(PermissionError, match="Access denied"):
        provider.discover_aws_config()
