from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.rds_rules import (
    check_rds_backup_retention,
    check_rds_deletion_protection,
    check_rds_public_accessibility,
    check_rds_storage_encryption,
)


def make_instance(**attributes):
    return Resource(
        resource_type="aws_db_instance",
        resource_id="customer-db",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_unencrypted_rds_instance_generates_high_finding():
    findings = check_rds_storage_encryption(make_instance(storage_encrypted=False))
    assert len(findings) == 1
    assert findings[0].check_id == "RDS-001"
    assert findings[0].severity == Severity.HIGH


def test_encrypted_or_unknown_rds_instance_is_not_flagged():
    assert check_rds_storage_encryption(make_instance(storage_encrypted=True)) == []
    assert check_rds_storage_encryption(make_instance()) == []


def test_publicly_accessible_rds_instance_generates_high_finding():
    findings = check_rds_public_accessibility(make_instance(publicly_accessible=True))
    assert len(findings) == 1
    assert findings[0].check_id == "RDS-002"
    assert findings[0].severity == Severity.HIGH


def test_private_or_unknown_rds_instance_is_not_flagged():
    assert check_rds_public_accessibility(make_instance(publicly_accessible=False)) == []
    assert check_rds_public_accessibility(make_instance()) == []


def test_short_rds_backup_retention_generates_medium_finding():
    findings = check_rds_backup_retention(make_instance(backup_retention_period=3))
    assert len(findings) == 1
    assert findings[0].check_id == "RDS-003"
    assert findings[0].severity == Severity.MEDIUM


def test_rds_backup_retention_of_seven_days_or_more_is_not_flagged():
    assert check_rds_backup_retention(make_instance(backup_retention_period=7)) == []
    assert check_rds_backup_retention(make_instance(backup_retention_period=14)) == []


def test_unknown_rds_backup_retention_is_not_flagged():
    assert check_rds_backup_retention(make_instance()) == []
    assert check_rds_backup_retention(make_instance(backup_retention_period=None)) == []


def test_rds_without_deletion_protection_generates_medium_finding():
    findings = check_rds_deletion_protection(make_instance(deletion_protection=False))
    assert len(findings) == 1
    assert findings[0].check_id == "RDS-004"
    assert findings[0].severity == Severity.MEDIUM


def test_rds_with_deletion_protection_or_unknown_is_not_flagged():
    assert check_rds_deletion_protection(make_instance(deletion_protection=True)) == []
    assert check_rds_deletion_protection(make_instance()) == []
