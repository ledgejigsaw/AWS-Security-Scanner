from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.waf_rules import check_alb_legacy_tls_policy


def alb(*, scheme="internet-facing", listeners=None):
    return Resource(
        resource_type="aws_lb",
        resource_id="arn:aws:elasticloadbalancing:eu-west-2:111111111111:loadbalancer/app/example/123",
        attributes={
            "scheme": scheme,
            "listeners": listeners if listeners is not None else [],
        },
        source="aws",
        region="eu-west-2",
    )


def test_alb_legacy_tls_rule_flags_known_policy_that_allows_deprecated_protocols():
    findings = check_alb_legacy_tls_policy(
        alb(listeners=[{
            "protocol": "HTTPS",
            "port": 443,
            "ssl_policy": "ELBSecurityPolicy-2016-08",
        }])
    )

    assert len(findings) == 1
    assert findings[0].check_id == "ALB-004"
    assert findings[0].severity.value == "MEDIUM"
    assert findings[0].evidence == "legacy_tls_policies=ELBSecurityPolicy-2016-08"


def test_alb_legacy_tls_rule_ignores_modern_unknown_and_non_https_policies():
    assert check_alb_legacy_tls_policy(
        alb(listeners=[{"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06"}])
    ) == []
    assert check_alb_legacy_tls_policy(
        alb(listeners=[{"protocol": "HTTPS", "ssl_policy": "FuturePolicy-unknown"}])
    ) == []
    assert check_alb_legacy_tls_policy(
        alb(listeners=[{"protocol": "HTTP", "ssl_policy": "ELBSecurityPolicy-2016-08"}])
    ) == []
    assert check_alb_legacy_tls_policy(
        alb(scheme="internal", listeners=[{"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-2016-08"}])
    ) == []


def test_alb_legacy_tls_rule_does_not_infer_policy_when_metadata_is_missing():
    assert check_alb_legacy_tls_policy(
        alb(listeners=[{"protocol": "HTTPS"}])
    ) == []
    assert check_alb_legacy_tls_policy(alb(listeners=None)) == []
