from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.decorators import rule_for


def test_rule_for_assigns_resource_type():
    @rule_for(
        "aws_s3_bucket",
        check_id="TEST-001",
        service="S3",
        severity=Severity.LOW,
        category="Test",
        title="Test rule",
        description="Test description",
        remediation="Test remediation",
    )
    def test_rule(resource):
        return []

    assert test_rule.resource_type == "aws_s3_bucket"


def test_rule_for_preserves_rule_callable():
    @rule_for(
        "aws_s3_bucket",
        check_id="TEST-002",
        service="S3",
        severity=Severity.LOW,
        category="Test",
        title="Test rule",
        description="Test description",
        remediation="Test remediation",
    )
    def test_rule(resource):
        return []

    assert callable(test_rule)


def test_rule_for_assigns_rule_metadata():
    @rule_for(
        "aws_s3_bucket",
        check_id="S3-001",
        service="S3",
        severity=Severity.CRITICAL,
        category="Access Control",
        title="S3 bucket is publicly accessible",
        description="The bucket is publicly accessible.",
        remediation="Enable S3 Block Public Access.",
    )
    def test_rule(resource):
        return []

    assert test_rule.metadata.check_id == "S3-001"
    assert test_rule.metadata.service == "S3"
    assert test_rule.metadata.resource_type == "aws_s3_bucket"
    assert test_rule.metadata.severity == Severity.CRITICAL
    assert test_rule.metadata.category == "Access Control"
    assert test_rule.metadata.title == "S3 bucket is publicly accessible"


def test_rule_for_metadata_matches_resource_type():
    @rule_for(
        "aws_iam_policy",
        check_id="IAM-001",
        service="IAM",
        severity=Severity.CRITICAL,
        category="Access Control",
        title="IAM policy grants unrestricted permissions",
        description="The policy grants unrestricted permissions.",
        remediation="Apply least privilege.",
    )
    def test_rule(resource):
        return []

    assert test_rule.metadata.resource_type == test_rule.resource_type