from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.registry import get_all_rules
from aws_security_scanner.rules.security_services_rules import (
    check_config_delivery_channel_missing,
    check_config_recorder_missing,
    check_config_recorder_stopped,
)


def config_resource(**attributes):
    return Resource(
        resource_type="aws_config_service",
        resource_id="aws-config:eu-west-2",
        attributes=attributes,
        source="aws",
        region="eu-west-2",
    )


def test_config_rules_are_registered_with_unique_check_ids():
    ids = [rule.metadata.check_id for rule in get_all_rules()]
    assert ids.count("CONFIG-001") == 1
    assert ids.count("CONFIG-002") == 1
    assert ids.count("CONFIG-003") == 1


def test_missing_recorder_rule_requires_explicit_false():
    assert check_config_recorder_missing(config_resource(recorder_configured=False))[0].check_id == "CONFIG-001"
    assert check_config_recorder_missing(config_resource(recorder_configured=None)) == []
    assert check_config_recorder_missing(config_resource(recorder_configured=True)) == []


def test_stopped_recorder_rule_requires_explicit_false():
    assert check_config_recorder_stopped(config_resource(recording=False))[0].check_id == "CONFIG-002"
    assert check_config_recorder_stopped(config_resource(recording=None)) == []
    assert check_config_recorder_stopped(config_resource(recording=True)) == []


def test_missing_delivery_channel_rule_requires_explicit_false():
    assert check_config_delivery_channel_missing(config_resource(delivery_channel_configured=False))[0].check_id == "CONFIG-003"
    assert check_config_delivery_channel_missing(config_resource(delivery_channel_configured=None)) == []
    assert check_config_delivery_channel_missing(config_resource(delivery_channel_configured=True)) == []
