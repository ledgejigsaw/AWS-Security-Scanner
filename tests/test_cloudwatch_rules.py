from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.cloudwatch_rules import (
    check_cloudwatch_alarm_actions,
    check_cloudwatch_log_group_retention,
)


def resource(resource_type, attributes, resource_id="example"):
    return Resource(
        resource_type=resource_type,
        resource_id=resource_id,
        attributes=attributes,
        source="aws",
        region="eu-west-2",
    )


def test_cloudwatch_retention_rule_flags_only_missing_explicit_retention():
    assert check_cloudwatch_log_group_retention(
        resource("aws_cloudwatch_log_group", {"retention_in_days": None}, "/app/unbounded")
    )[0].check_id == "CW-001"
    assert check_cloudwatch_log_group_retention(
        resource("aws_cloudwatch_log_group", {"retention_in_days": 90}, "/app/retained")
    ) == []


def test_cloudwatch_alarm_rule_is_an_informational_review_signal():
    assert check_cloudwatch_alarm_actions(
        resource("aws_cloudwatch_metric_alarm", {"actions_enabled": False, "alarm_actions": []})
    )[0].severity.value == "INFO"
    assert check_cloudwatch_alarm_actions(
        resource("aws_cloudwatch_metric_alarm", {"actions_enabled": True, "alarm_actions": ["arn:example"]})
    ) == []
