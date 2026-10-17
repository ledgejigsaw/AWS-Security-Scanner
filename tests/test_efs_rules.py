from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.efs_rules import (
    check_efs_access_point_root_identity,
    check_efs_encryption_disabled,
)


def resource(resource_type, attributes, resource_id="example"):
    return Resource(
        resource_type=resource_type,
        resource_id=resource_id,
        attributes=attributes,
        source="aws",
        region="eu-west-2",
    )


def test_efs_encryption_rule_flags_only_explicit_unencrypted_state():
    assert check_efs_encryption_disabled(
        resource("aws_efs_file_system", {"encrypted": False}, "fs-123")
    )[0].check_id == "EFS-001"
    assert check_efs_encryption_disabled(
        resource("aws_efs_file_system", {"encrypted": True})
    ) == []
    assert check_efs_encryption_disabled(
        resource("aws_efs_file_system", {"encrypted": None})
    ) == []


def test_efs_root_access_point_is_only_an_informational_review_signal():
    finding = check_efs_access_point_root_identity(
        resource("aws_efs_access_point", {"posix_user": {"Uid": 0, "Gid": 0}}, "fsap-123")
    )[0]
    assert finding.check_id == "EFS-002"
    assert finding.severity.value == "INFO"
    assert check_efs_access_point_root_identity(
        resource("aws_efs_access_point", {"posix_user": {"Uid": 1000, "Gid": 1000}})
    ) == []
    assert check_efs_access_point_root_identity(
        resource("aws_efs_access_point", {"posix_user": None})
    ) == []
