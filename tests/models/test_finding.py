from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.rules.decorators import rule_for


def test_finding_can_be_created_from_rule_metadata():
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

    finding = Finding.from_rule(
        test_rule,
        resource="example-bucket",
        region="eu-west-2",
        evidence="public=true",
    )

    assert finding.check_id == "S3-001"
    assert finding.severity == Severity.CRITICAL
    assert finding.service == "S3"
    assert finding.resource == "example-bucket"
    assert finding.title == "S3 bucket is publicly accessible"
    assert finding.description == "The bucket is publicly accessible."
    assert finding.remediation == "Enable S3 Block Public Access."
    assert finding.region == "eu-west-2"
    assert finding.evidence == "public=true"