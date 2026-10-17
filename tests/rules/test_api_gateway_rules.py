from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.api_gateway_rules import (
    check_api_gateway_unauthenticated_methods,
    check_api_gateway_access_logging_disabled,
)


def stage(**attributes):
    return Resource(
        resource_type="aws_api_gateway_stage",
        resource_id="abc123:prod",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_unauthenticated_method_without_resource_policy_generates_finding():
    findings = check_api_gateway_unauthenticated_methods(stage(
        methods=[
            {"path": "/payments", "http_method": "POST", "authorization_type": "NONE"},
            {"path": "/health", "http_method": "GET", "authorization_type": "AWS_IAM"},
        ],
        resource_policy=None,
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "APIGW-001"
    assert findings[0].severity == Severity.HIGH
    assert "POST /payments" in findings[0].evidence


def test_auth_rule_does_not_flag_configured_authorization_or_policy():
    assert check_api_gateway_unauthenticated_methods(stage(
        methods=[{"path": "/", "http_method": "GET", "authorization_type": "AWS_IAM"}],
        resource_policy=None,
    )) == []
    assert check_api_gateway_unauthenticated_methods(stage(
        methods=[{"path": "/", "http_method": "GET", "authorization_type": "NONE"}],
        resource_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*"}]}',
    )) == []
    assert check_api_gateway_unauthenticated_methods(stage(methods=None, resource_policy=None)) == []
    assert check_api_gateway_unauthenticated_methods(stage(methods=[{"path": "/"}], resource_policy=None)) == []


def test_access_logging_rule_flags_explicit_missing_settings():
    findings = check_api_gateway_access_logging_disabled(stage(
        access_logging_enabled=False,
        access_log_destination_arn=None,
        access_log_format=None,
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "APIGW-002"
    assert findings[0].severity == Severity.MEDIUM


def test_access_logging_rule_does_not_flag_enabled_or_unknown_state():
    assert check_api_gateway_access_logging_disabled(stage(access_logging_enabled=True)) == []
    assert check_api_gateway_access_logging_disabled(stage()) == []


def http_stage(**attributes):
    return Resource(resource_type="aws_api_gateway_http_api_stage", resource_id="http123:$default", attributes=attributes, source="fixture", region="eu-west-2")


def test_http_api_unauthenticated_route_generates_finding():
    findings = __import__("aws_security_scanner.rules.api_gateway_rules", fromlist=["check_api_gateway_http_api_unauthenticated_routes"]).check_api_gateway_http_api_unauthenticated_routes(
        http_stage(routes=[{"route_key": "POST /payments", "authorization_type": "NONE"}])
    )
    assert len(findings) == 1
    assert findings[0].check_id == "APIGW-003"
    assert findings[0].severity == Severity.HIGH


def test_http_api_access_logging_rule():
    module = __import__("aws_security_scanner.rules.api_gateway_rules", fromlist=["check_api_gateway_http_api_access_logging_disabled"])
    assert module.check_api_gateway_http_api_access_logging_disabled(http_stage(access_logging_enabled=False)) 
    assert module.check_api_gateway_http_api_access_logging_disabled(http_stage(access_logging_enabled=True)) == []
    assert module.check_api_gateway_http_api_access_logging_disabled(http_stage()) == []
