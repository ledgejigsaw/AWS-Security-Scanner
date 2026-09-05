from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource


def test_rule_engine_runs_rule_against_resource():
    def test_rule(resource: Resource) -> list[Finding]:
        return [
            Finding(
                check_id="TEST-001",
                severity=Severity.LOW,
                service="TEST",
                resource=resource.resource_id,
                title="Test finding",
                description="Test description",
                remediation="Test remediation",
            )
        ]

    test_rule.resource_type = "aws_s3_bucket"

    engine = RuleEngine([test_rule])

    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="test-bucket",
        attributes={},
        source="test",
    )

    findings = engine.scan([resource])

    assert len(findings) == 1
    assert findings[0].check_id == "TEST-001"


def test_rule_engine_runs_multiple_rules():
    def rule_one(resource: Resource) -> list[Finding]:
        return [
            Finding(
                check_id="TEST-001",
                severity=Severity.LOW,
                service="TEST",
                resource=resource.resource_id,
                title="First finding",
                description="First description",
                remediation="First remediation",
            )
        ]

    def rule_two(resource: Resource) -> list[Finding]:
        return [
            Finding(
                check_id="TEST-002",
                severity=Severity.MEDIUM,
                service="TEST",
                resource=resource.resource_id,
                title="Second finding",
                description="Second description",
                remediation="Second remediation",
            )
        ]

    rule_one.resource_type = "aws_s3_bucket"
    rule_two.resource_type = "aws_s3_bucket"

    engine = RuleEngine([rule_one, rule_two])

    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="test-bucket",
        attributes={},
        source="test",
    )

    findings = engine.scan([resource])

    assert len(findings) == 2
    assert findings[0].check_id == "TEST-001"
    assert findings[1].check_id == "TEST-002"


def test_rule_engine_only_runs_rules_for_matching_resource_type():
    def s3_rule(resource: Resource) -> list[Finding]:
        return [
            Finding(
                check_id="S3-TEST",
                severity=Severity.LOW,
                service="S3",
                resource=resource.resource_id,
                title="S3 test finding",
                description="S3 test description",
                remediation="S3 test remediation",
            )
        ]

    s3_rule.resource_type = "aws_s3_bucket"

    engine = RuleEngine([s3_rule])

    s3_resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="test-bucket",
        attributes={},
        source="test",
    )

    ec2_resource = Resource(
        resource_type="aws_instance",
        resource_id="test-instance",
        attributes={},
        source="test",
    )

    findings = engine.scan([s3_resource, ec2_resource])

    assert len(findings) == 1
    assert findings[0].check_id == "S3-TEST"
    assert findings[0].resource == "test-bucket"