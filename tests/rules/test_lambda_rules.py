from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.lambda_rules import (
    check_lambda_public_function_url,
    check_lambda_wildcard_invoke_policy,
)


def make_function(**attributes):
    return Resource(
        resource_type="aws_lambda_function",
        resource_id="customer-handler",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_function_url_without_iam_auth_generates_high_finding():
    findings = check_lambda_public_function_url(
        make_function(function_url_auth_type="NONE")
    )
    assert len(findings) == 1
    assert findings[0].check_id == "LAMBDA-001"
    assert findings[0].severity == Severity.HIGH


def test_iam_authenticated_or_missing_function_url_is_not_flagged():
    assert check_lambda_public_function_url(
        make_function(function_url_auth_type="AWS_IAM")
    ) == []
    assert check_lambda_public_function_url(make_function()) == []


def test_unconditional_wildcard_invoke_policy_generates_high_finding():
    resource = make_function(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
            }]
        }
    )
    findings = check_lambda_wildcard_invoke_policy(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "LAMBDA-002"
    assert findings[0].severity == Severity.HIGH


def test_wildcard_policy_with_condition_is_not_flagged():
    resource = make_function(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
            }]
        }
    )
    assert check_lambda_wildcard_invoke_policy(resource) == []


def test_specific_principal_is_not_flagged():
    resource = make_function(
        resource_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                "Action": "lambda:InvokeFunction",
                "Resource": "*",
            }]
        }
    )
    assert check_lambda_wildcard_invoke_policy(resource) == []


def test_policy_json_string_is_parsed():
    resource = make_function(
        resource_policy='{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:*","Resource":"*"}]}'
    )
    assert check_lambda_wildcard_invoke_policy(resource)[0].check_id == "LAMBDA-002"


def test_unknown_or_malformed_policy_is_not_flagged():
    assert check_lambda_wildcard_invoke_policy(make_function()) == []
    assert check_lambda_wildcard_invoke_policy(
        make_function(resource_policy="{invalid")
    ) == []
