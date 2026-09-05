from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource


def test_rule_engine_runs_rule_against_resource():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="test-bucket",
        attributes={},
        source="fixture",
        region="eu-west-2",
    )

    def test_rule(resource):
        return [
            Finding(
                check_id="TEST-001",
                severity=Severity.HIGH,
                service="TEST",
                resource=resource.resource_id,
                title="Test finding",
                description="Test description",
                remediation="Test remediation",
                region=resource.region,
                evidence="test=true",
            )
        ]

    engine = RuleEngine([test_rule])

    findings = engine.scan([resource])

    assert len(findings) == 1
    assert findings[0].check_id == "TEST-001"
    assert findings[0].resource == "test-bucket"


def test_rule_engine_runs_multiple_rules():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="test-bucket",
        attributes={},
        source="fixture",
        region="eu-west-2",
    )

    def rule_one(resource):
        return [
            Finding(
                check_id="TEST-001",
                severity=Severity.HIGH,
                service="TEST",
                resource=resource.resource_id,
                title="Finding one",
                description="Description one",
                remediation="Remediation one",
            )
        ]

    def rule_two(resource):
        return [
            Finding(
                check_id="TEST-002",
                severity=Severity.MEDIUM,
                service="TEST",
                resource=resource.resource_id,
                title="Finding two",
                description="Description two",
                remediation="Remediation two",
            )
        ]

    engine = RuleEngine([rule_one, rule_two])

    findings = engine.scan([resource])

    assert len(findings) == 2
    assert findings[0].check_id == "TEST-001"
    assert findings[1].check_id == "TEST-002"