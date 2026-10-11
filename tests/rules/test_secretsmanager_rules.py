from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.secretsmanager_rules import (
    check_secret_rotation_disabled,
    check_secret_wildcard_resource_policy,
)


def make_secret(**attributes):
    return Resource(
        resource_type="aws_secretsmanager_secret",
        resource_id="customer-api-token",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_explicitly_disabled_rotation_generates_medium_finding():
    findings = check_secret_rotation_disabled(make_secret(rotation_enabled=False))
    assert len(findings) == 1
    assert findings[0].check_id == "SM-001"
    assert findings[0].severity == Severity.MEDIUM


def test_enabled_or_unknown_rotation_is_not_flagged():
    assert check_secret_rotation_disabled(make_secret(rotation_enabled=True)) == []
    assert check_secret_rotation_disabled(make_secret()) == []


def test_unconditional_wildcard_secret_policy_generates_critical_finding():
    resource = make_secret(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }]
        }
    )
    findings = check_secret_wildcard_resource_policy(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "SM-002"
    assert findings[0].severity == Severity.CRITICAL


def test_policy_condition_prevents_wildcard_finding():
    resource = make_secret(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
            }]
        }
    )
    assert check_secret_wildcard_resource_policy(resource) == []


def test_specific_principal_does_not_generate_wildcard_finding():
    resource = make_secret(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }]
        }
    )
    assert check_secret_wildcard_resource_policy(resource) == []


def test_json_policy_string_is_parsed_without_secret_material():
    resource = make_secret(
        resource_policy='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:*","Resource":"*"}]}'
    )
    assert check_secret_wildcard_resource_policy(resource)[0].check_id == "SM-002"


def test_malformed_or_unavailable_policy_is_not_flagged():
    assert check_secret_wildcard_resource_policy(make_secret()) == []
    assert check_secret_wildcard_resource_policy(
        make_secret(resource_policy="{invalid")
    ) == []

def test_unrelated_service_wildcard_action_is_not_flagged():
    resource = make_secret(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
            }]
        }
    )
    assert check_secret_wildcard_resource_policy(resource) == []
