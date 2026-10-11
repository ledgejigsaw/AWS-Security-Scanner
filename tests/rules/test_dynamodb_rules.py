from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.dynamodb_rules import (
    check_dynamodb_deletion_protection_disabled,
    check_dynamodb_pitr_disabled,
    check_dynamodb_sse_disabled,
)


def table(**attributes):
    return Resource(
        resource_type="aws_dynamodb_table",
        resource_id="payments",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_disabled_pitr_generates_medium_finding():
    findings = check_dynamodb_pitr_disabled(
        table(point_in_time_recovery_status="DISABLED")
    )
    assert len(findings) == 1
    assert findings[0].check_id == "DDB-001"
    assert findings[0].severity == Severity.MEDIUM


def test_enabled_or_unknown_pitr_is_not_flagged():
    assert check_dynamodb_pitr_disabled(table(point_in_time_recovery_status="ENABLED")) == []
    assert check_dynamodb_pitr_disabled(table()) == []


def test_explicitly_disabled_sse_generates_high_finding():
    findings = check_dynamodb_sse_disabled(table(sse_status="DISABLED"))
    assert len(findings) == 1
    assert findings[0].check_id == "DDB-002"
    assert findings[0].severity == Severity.HIGH


def test_enabled_or_unknown_sse_is_not_flagged():
    assert check_dynamodb_sse_disabled(table(sse_status="ENABLED")) == []
    assert check_dynamodb_sse_disabled(table()) == []


def test_disabled_deletion_protection_generates_medium_finding():
    findings = check_dynamodb_deletion_protection_disabled(
        table(deletion_protection_enabled=False)
    )
    assert len(findings) == 1
    assert findings[0].check_id == "DDB-003"
    assert findings[0].severity == Severity.MEDIUM


def test_enabled_or_unknown_deletion_protection_is_not_flagged():
    assert check_dynamodb_deletion_protection_disabled(
        table(deletion_protection_enabled=True)
    ) == []
    assert check_dynamodb_deletion_protection_disabled(table()) == []
