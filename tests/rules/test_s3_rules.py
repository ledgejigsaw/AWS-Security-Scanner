from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.rule import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.s3_rules import (
    check_public_bucket,
    check_encryption,
    check_versioning,
    check_block_public_access,
    check_logging,
    check_wildcard_bucket_policy,
    check_tls_enforcement,
    check_excessive_s3_actions,
    check_wildcard_bucket_resource,
    check_public_write_access,
    check_insecure_transport,
    check_public_acl,
    check_acl_object_ownership,
    check_mfa_delete,
    
)


def test_public_bucket_generates_critical_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "public": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_bucket(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_private_bucket_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "public": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_bucket(resource)

    assert findings == []


def test_unencrypted_bucket_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "encryption": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_encryption(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-002"
    assert findings[0].severity == Severity.HIGH


def test_encrypted_bucket_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "encryption": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_encryption(resource)

    assert findings == []


def test_versioning_disabled_generates_medium_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "versioning": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_versioning(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-003"
    assert findings[0].severity == Severity.MEDIUM


def test_versioning_enabled_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "versioning": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_versioning(resource)

    assert findings == []


def test_block_public_access_disabled_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "block_public_access": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_block_public_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-004"
    assert findings[0].severity == Severity.HIGH


def test_block_public_access_enabled_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "block_public_access": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_block_public_access(resource)

    assert findings == []


def test_logging_disabled_generates_medium_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "logging": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_logging(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-005"
    assert findings[0].severity == Severity.MEDIUM


def test_logging_enabled_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "bucket_name": "company-data",
            "logging": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_logging(resource)

    assert findings == []


def test_bucket_policy_with_wildcard_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_wildcard_aws_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "s3:GetObject",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"


def test_bucket_policy_with_wildcard_federated_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "*"
                        },
                        "Action": "s3:GetObject",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"


def test_bucket_policy_with_wildcard_service_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "*"
                        },
                        "Action": "s3:GetObject",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"


def test_bucket_policy_deny_wildcard_principal_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert findings == []


def test_bucket_policy_with_specific_service_principal_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "logging.s3.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert findings == []


def test_bucket_without_policy_generates_no_s3_006_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert findings == []


def test_bucket_policy_with_single_statement_dict_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                },
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"


def test_bucket_policy_without_tls_enforcement_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:GetObject",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_tls_enforcement(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-007"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_tls_enforcement_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false"
                            }
                        },
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_tls_enforcement(resource)

    assert findings == []


def test_bucket_without_policy_generates_high_tls_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_tls_enforcement(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-007"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_single_statement_dict_for_tls_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                },
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_tls_enforcement(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-007"


# S3-008

def test_bucket_policy_with_wildcard_s3_action_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:*",
                        "Resource": [
                            "arn:aws:s3:::company-sensitive-data",
                            "arn:aws:s3:::company-sensitive-data/*",
                        ],
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-008"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_specific_s3_actions_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                        ],
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert findings == []


def test_bucket_policy_with_multiple_actions_including_wildcard_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": [
                            "s3:GetObject",
                            "s3:*",
                        ],
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-008"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_deny_with_wildcard_s3_action_generates_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert findings == []


def test_bucket_without_policy_generates_no_s3_008_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert findings == []


def test_bucket_policy_with_single_statement_dict_for_s3_008_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            "arn:aws:iam::123456789012:"
                            "role/application"
                        )
                    },
                    "Action": "s3:*",
                },
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_excessive_s3_actions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-008"
    assert findings[0].severity == Severity.HIGH

def test_bucket_policy_with_wildcard_resource_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_resource(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-009"
    assert findings[0].severity == Severity.HIGH

def test_bucket_policy_with_specific_resources_generates_no_s3_009_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:GetObject",
                        "Resource": [
                            "arn:aws:s3:::company-sensitive-data",
                            "arn:aws:s3:::company-sensitive-data/*",
                        ],
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_resource(resource)

    assert findings == []

def test_bucket_policy_with_multiple_resources_including_wildcard_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:GetObject",
                        "Resource": [
                            "arn:aws:s3:::company-sensitive-data/*",
                            "*",
                        ],
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_resource(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-009"
    assert findings[0].severity == Severity.HIGH

def test_bucket_policy_deny_with_wildcard_resource_generates_no_s3_009_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_resource(resource)

    assert findings == []

def test_bucket_policy_with_public_write_access_generates_critical_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-010"
    assert findings[0].severity == Severity.CRITICAL

def test_bucket_policy_with_public_read_access_generates_no_s3_010_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert findings == []

def test_bucket_policy_with_public_delete_access_generates_critical_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:DeleteObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-010"
    assert findings[0].severity == Severity.CRITICAL

def test_bucket_policy_with_public_wildcard_action_generates_critical_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-010"
    assert findings[0].severity == Severity.CRITICAL

def test_bucket_policy_with_specific_principal_write_access_generates_no_s3_010_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/application"
                            )
                        },
                        "Action": "s3:PutObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert findings == []

def test_bucket_policy_deny_with_public_write_access_generates_no_s3_010_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": (
                            "arn:aws:s3:::company-sensitive-data/*"
                        ),
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert findings == []

def test_bucket_without_policy_generates_no_s3_010_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_write_access(resource)

    assert findings == []

def test_insecure_transport_bucket_policy_generates_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="insecure-transport-bucket",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_insecure_transport(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-008"
    assert findings[0].severity == Severity.HIGH

def test_secure_transport_bucket_policy_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="secure-transport-bucket",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "*",
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false"
                            }
                        },
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_insecure_transport(resource)

    assert findings == []

def test_public_acl_generates_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="public-acl-bucket",
        attributes={
            "acl": {
                "grants": [
                    {
                        "grantee": {
                            "type": "Group",
                            "uri": (
                                "http://acs.amazonaws.com/groups/"
                                "global/AllUsers"
                            ),
                        },
                        "permission": "READ",
                    }
                ]
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_acl(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-009"
    assert findings[0].severity == Severity.HIGH

def test_acl_object_ownership_not_hardened_generates_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="acl-enabled-bucket",
        attributes={
            "object_ownership": "BucketOwnerPreferred",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_acl_object_ownership(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-010"
    assert findings[0].severity == Severity.HIGH

def test_acl_object_ownership_hardened_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="secure-acl-bucket",
        attributes={
            "object_ownership": "BucketOwnerEnforced",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_acl_object_ownership(resource)

    assert findings == []


def test_mfa_delete_disabled_generates_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="mfa-delete-disabled-bucket",
        attributes={
            "versioning_configuration": {
                "status": "Enabled",
                "mfa_delete": "Disabled",
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_mfa_delete(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-011"
    assert findings[0].severity == Severity.MEDIUM

def test_mfa_delete_enabled_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="mfa-delete-enabled-bucket",
        attributes={
            "versioning_configuration": {
                "status": "Enabled",
                "mfa_delete": "Enabled",
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_mfa_delete(resource)

    assert findings == []