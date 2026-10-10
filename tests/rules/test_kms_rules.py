from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.kms_rules import (
    check_kms_key_pending_deletion,
    check_kms_key_rotation,
)


def make_key(**attributes):
    return Resource(
        resource_type="aws_kms_key",
        resource_id="arn:aws:kms:eu-west-2:123456789012:key/example",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_customer_managed_symmetric_key_without_rotation_generates_high_finding():
    findings = check_kms_key_rotation(
        make_key(
            rotation_applicable=True,
            rotation_enabled=False,
            key_manager="CUSTOMER",
        )
    )

    assert len(findings) == 1
    assert findings[0].check_id == "KMS-001"
    assert findings[0].severity == Severity.HIGH


def test_rotating_customer_managed_key_generates_no_finding():
    assert check_kms_key_rotation(
        make_key(rotation_applicable=True, rotation_enabled=True)
    ) == []


def test_rotation_check_ignores_keys_where_rotation_is_not_applicable():
    assert check_kms_key_rotation(
        make_key(rotation_applicable=False, rotation_enabled=None)
    ) == []


def test_key_pending_deletion_generates_medium_finding():
    findings = check_kms_key_pending_deletion(
        make_key(key_state="PendingDeletion")
    )

    assert len(findings) == 1
    assert findings[0].check_id == "KMS-002"
    assert findings[0].severity == Severity.MEDIUM


def test_enabled_key_generates_no_pending_deletion_finding():
    assert check_kms_key_pending_deletion(make_key(key_state="Enabled")) == []
