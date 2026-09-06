from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.iam_rules import (
    check_overly_permissive_policy,
    check_wildcard_permissions,
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
)


def test_overly_permissive_policy_is_critical():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="AdministratorLikePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_overly_permissive_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-001"
    assert findings[0].severity == Severity.CRITICAL


def test_restricted_policy_does_not_trigger():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="RestrictedS3Policy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": "arn:aws:s3:::company-secure-data/*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_overly_permissive_policy(resource)

    assert findings == []


def test_deny_statement_does_not_trigger():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyAllPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_overly_permissive_policy(resource)

    assert findings == []


def test_single_statement_dict_is_supported():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SingleStatementPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
            }
        },
        source="fixture",
    )

    findings = check_overly_permissive_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-001"

def test_wildcard_action_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="S3WildcardActionPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_wildcard_resource_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="WildcardResourcePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_unrestricted_policy_does_not_duplicate_iam_001():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="AdministratorLikePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []


def test_restricted_policy_does_not_trigger_wildcard_check():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="RestrictedS3Policy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-secure-data/*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []

def test_high_risk_administrative_permission_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="IAMAdminPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreateUser",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-003"
    assert findings[0].severity == Severity.HIGH


def test_high_risk_administrative_action_in_action_list_generates_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="IAMAdminActionList",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "iam:PassRole",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-003"
    assert findings[0].severity == Severity.HIGH


def test_restricted_iam_permission_does_not_trigger_admin_check():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="RestrictedPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []


def test_deny_high_risk_permission_does_not_trigger_admin_check():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DeniedAdminPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "iam:CreateRole",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []

def test_wildcard_trust_policy_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="PublicAssumableRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-004"
    assert findings[0].severity == Severity.HIGH

def test_wildcard_aws_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="WildcardAWSPrincipalRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-004"
    assert findings[0].severity == Severity.HIGH

def test_restricted_service_trust_policy_does_not_trigger():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="EC2ApplicationRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert findings == []
    
def test_deny_wildcard_trust_policy_does_not_trigger():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="DeniedWildcardRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert findings == []

def test_service_action_prefix_wildcard_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="S3ReadPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:Get*",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_action_prefix_wildcard_in_list_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MixedPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:Put*",
                        ],
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_specific_action_has_no_wildcard_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SpecificS3Policy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []


def test_deny_action_prefix_wildcard_has_no_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "s3:Get*",
                        "Resource": "*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []

def test_service_action_prefix_wildcard_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="S3ReadPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:Get*",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_action_prefix_wildcard_in_list_generates_high_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MixedPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:Put*",
                        ],
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


def test_specific_action_has_no_wildcard_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SpecificS3Policy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-data/*",
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []


def test_deny_action_prefix_wildcard_has_no_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "s3:Get*",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []