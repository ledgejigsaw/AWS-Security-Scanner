from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.rule import RuleMetadata


def test_rule_metadata_can_be_created():
    metadata = RuleMetadata(
        check_id="S3-001",
        service="S3",
        resource_type="aws_s3_bucket",
        severity=Severity.CRITICAL,
        category="Access Control",
        title="S3 bucket is publicly accessible",
        description="The bucket is publicly accessible.",
        remediation="Enable S3 Block Public Access.",
    )

    assert metadata.check_id == "S3-001"
    assert metadata.service == "S3"
    assert metadata.resource_type == "aws_s3_bucket"
    assert metadata.severity == Severity.CRITICAL
    assert metadata.category == "Access Control"


def test_rule_metadata_is_immutable():
    metadata = RuleMetadata(
        check_id="S3-001",
        service="S3",
        resource_type="aws_s3_bucket",
        severity=Severity.CRITICAL,
        category="Access Control",
        title="S3 bucket is publicly accessible",
        description="The bucket is publicly accessible.",
        remediation="Enable S3 Block Public Access.",
    )

    try:
        metadata.check_id = "S3-999"
    except AttributeError:
        pass
    else:
        raise AssertionError("RuleMetadata should be immutable")