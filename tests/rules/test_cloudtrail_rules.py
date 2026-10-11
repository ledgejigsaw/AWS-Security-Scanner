from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.cloudtrail_rules import (
    check_cloudtrail_logging,
    check_cloudtrail_multi_region,
)


def make_trail(**attributes):
    return Resource(
        resource_type="aws_cloudtrail_trail",
        resource_id="arn:aws:cloudtrail:eu-west-2:123456789012:trail/org",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_cloudtrail_not_logging_generates_high_finding():
    findings = check_cloudtrail_logging(make_trail(is_logging=False))

    assert len(findings) == 1
    assert findings[0].check_id == "CT-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence == "is_logging=false"


def test_cloudtrail_logging_generates_no_finding():
    assert check_cloudtrail_logging(make_trail(is_logging=True)) == []


def test_cloudtrail_multi_region_disabled_generates_medium_finding():
    findings = check_cloudtrail_multi_region(
        make_trail(is_multi_region_trail=False)
    )

    assert len(findings) == 1
    assert findings[0].check_id == "CT-002"
    assert findings[0].severity == Severity.MEDIUM


def test_multi_region_cloudtrail_generates_no_finding():
    assert (
        check_cloudtrail_multi_region(
            make_trail(is_multi_region_trail=True)
        )
        == []
    )



def test_cloudtrail_log_file_validation_disabled_generates_medium_finding():
    from aws_security_scanner.rules.cloudtrail_rules import (
        check_cloudtrail_log_file_validation,
    )

    findings = check_cloudtrail_log_file_validation(
        make_trail(log_file_validation_enabled=False)
    )

    assert len(findings) == 1
    assert findings[0].check_id == "CT-003"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence == "log_file_validation_enabled=false"


def test_cloudtrail_log_file_validation_enabled_generates_no_finding():
    from aws_security_scanner.rules.cloudtrail_rules import (
        check_cloudtrail_log_file_validation,
    )

    assert check_cloudtrail_log_file_validation(
        make_trail(log_file_validation_enabled=True)
    ) == []
