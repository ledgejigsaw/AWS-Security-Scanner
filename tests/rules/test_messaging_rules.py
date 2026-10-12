from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.messaging_rules import (
    check_sqs_public_access_policy,
    check_sqs_encryption_disabled,
    check_sns_public_access_policy,
    check_sns_encryption_disabled,
)


def resource(resource_type, name, **attributes):
    return Resource(
        resource_type=resource_type,
        resource_id=name,
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_unconditional_wildcard_sqs_policy_generates_critical_finding():
    findings = check_sqs_public_access_policy(resource(
        "aws_sqs_queue", "orders",
        policy={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}]},
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "SQS-001"
    assert findings[0].severity == Severity.CRITICAL


def test_sqs_policy_with_condition_or_restricted_principal_is_not_flagged():
    assert check_sqs_public_access_policy(resource(
        "aws_sqs_queue", "orders",
        policy={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Condition": {"StringEquals": {"aws:SourceAccount": "123"}}}]},
    )) == []
    assert check_sqs_public_access_policy(resource(
        "aws_sqs_queue", "orders",
        policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/worker"}, "Action": "sqs:SendMessage"}]},
    )) == []
    assert check_sqs_public_access_policy(resource("aws_sqs_queue", "orders", policy="not-json")) == []


def test_sqs_encryption_rule_requires_explicit_disabled_state():
    findings = check_sqs_encryption_disabled(resource("aws_sqs_queue", "orders", encryption_enabled=False))
    assert len(findings) == 1
    assert findings[0].check_id == "SQS-002"
    assert findings[0].severity == Severity.HIGH
    assert check_sqs_encryption_disabled(resource("aws_sqs_queue", "orders", encryption_enabled=True)) == []
    assert check_sqs_encryption_disabled(resource("aws_sqs_queue", "orders")) == []


def test_unconditional_wildcard_sns_policy_generates_critical_finding():
    findings = check_sns_public_access_policy(resource(
        "aws_sns_topic", "alerts",
        policy='{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["sns:Publish"]}]}',
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "SNS-001"
    assert findings[0].severity == Severity.CRITICAL


def test_sns_policy_with_condition_or_restricted_action_is_not_flagged():
    assert check_sns_public_access_policy(resource(
        "aws_sns_topic", "alerts",
        policy={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Condition": {"StringEquals": {"aws:SourceOwner": "123"}}}]},
    )) == []
    assert check_sns_public_access_policy(resource(
        "aws_sns_topic", "alerts",
        policy={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:GetTopicAttributes"}]},
    )) == []


def test_sns_encryption_rule_requires_explicit_disabled_state():
    findings = check_sns_encryption_disabled(resource("aws_sns_topic", "alerts", encryption_enabled=False))
    assert len(findings) == 1
    assert findings[0].check_id == "SNS-002"
    assert findings[0].severity == Severity.HIGH
    assert check_sns_encryption_disabled(resource("aws_sns_topic", "alerts", encryption_enabled=True)) == []
    assert check_sns_encryption_disabled(resource("aws_sns_topic", "alerts")) == []
