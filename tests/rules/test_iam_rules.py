from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.iam_rules import (
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
    check_overly_permissive_policy,
    check_wildcard_permissions,
)


# ---------------------------------------------------------------------------
# IAM-001 — Unrestricted IAM Permissions
# ---------------------------------------------------------------------------


def test_overly_permissive_policy_detects_unrestricted_permissions():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="AdminPolicy",
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
    assert findings[0].resource == "AdminPolicy"


def test_overly_permissive_policy_ignores_restricted_permissions():
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

    findings = check_overly_permissive_policy(resource)

    assert findings == []


def test_overly_permissive_policy_ignores_deny_statement():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyPolicy",
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


def test_policy_without_document_has_no_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MissingPolicyDocument",
        attributes={},
        source="fixture",
    )

    findings = check_overly_permissive_policy(resource)

    assert findings == []


def test_overly_permissive_policy_accepts_single_statement_dict():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SingleStatementAdminPolicy",
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
    assert findings[0].severity == Severity.CRITICAL

def test_overly_permissive_policy_detects_wildcards_in_lists():

    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="ListWildcardAdminPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "*",
                            "iam:PassRole",
                        ],
                        "Resource": [
                            "*",
                        ],
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

# ---------------------------------------------------------------------------
# IAM-002 — Wildcard IAM Permissions
# ---------------------------------------------------------------------------


def test_wildcard_permissions_detect_wildcard_action():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="WildcardActionPolicy",
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


def test_wildcard_permissions_detect_wildcard_resource():
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


def test_wildcard_permissions_detect_wildcard_action_list():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="WildcardActionListPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:Delete*",
                        ],
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


def test_wildcard_permissions_detect_wildcard_action_prefix():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="WildcardPrefixPolicy",
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
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"


def test_wildcard_permissions_do_not_duplicate_iam001():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="UnrestrictedPolicy",
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


def test_wildcard_permissions_ignore_deny_statement():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyWildcardPolicy",
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

    findings = check_wildcard_permissions(resource)

    assert findings == []


def test_wildcard_permissions_without_document_have_no_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MissingWildcardPolicyDocument",
        attributes={},
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert findings == []


def test_wildcard_permissions_accept_single_statement_dict():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SingleStatementPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "s3:Get*",
                    "Resource": "arn:aws:s3:::company-data/*",
                },
            }
        },
        source="fixture",
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# IAM-003 — Excessive Administrative Permissions
# ---------------------------------------------------------------------------


def test_excessive_administrative_permissions_detect_create_user():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="CreateUserPolicy",
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


def test_excessive_administrative_permissions_detect_create_role():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="CreateRolePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreateRole",
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


def test_excessive_administrative_permissions_detect_attach_role_policy():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="AttachRolePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:AttachRolePolicy",
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


def test_excessive_administrative_permissions_detect_attach_user_policy():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="AttachUserPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:AttachUserPolicy",
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


def test_excessive_administrative_permissions_detect_multiple_actions():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MultipleAdminActions",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateUser",
                            "iam:CreateRole",
                            "s3:GetObject",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert len(findings) == 2
    assert all(
        finding.check_id == "IAM-003"
        for finding in findings
    )


def test_excessive_administrative_permissions_detect_pass_role():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="PassRolePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
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


def test_excessive_administrative_permissions_ignore_non_admin_action():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="NormalPolicy",
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

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []


def test_excessive_administrative_permissions_ignore_deny_statement():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="DenyAdminPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "iam:CreateUser",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []


def test_excessive_administrative_permissions_without_document_has_no_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="MissingAdminPolicyDocument",
        attributes={},
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []


def test_excessive_administrative_permissions_accepts_single_statement_dict():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="SingleStatementAdminPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "iam:CreateUser",
                    "Resource": "*",
                },
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-003"
    assert findings[0].severity == Severity.HIGH


def test_excessive_administrative_permissions_ignores_unsupported_action_type():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="InvalidActionType",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": {
                            "Name": "iam:CreateUser"
                        },
                        "Resource": "*",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_excessive_administrative_permissions(resource)

    assert findings == []


# ---------------------------------------------------------------------------
# IAM-004 — Insecure IAM Role Trust Policy
# ---------------------------------------------------------------------------


def test_insecure_trust_policy_detects_wildcard_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="InsecureRole",
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
    assert findings[0].resource == "InsecureRole"


def test_insecure_trust_policy_detects_wildcard_aws_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="WildcardAWSRole",
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


def test_insecure_trust_policy_detects_wildcard_federated_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="WildcardFederatedRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "*"
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


def test_insecure_trust_policy_allows_specific_aws_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="SpecificAWSRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": (
                                "arn:aws:iam::123456789012:"
                                "role/ApplicationRole"
                            )
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


def test_insecure_trust_policy_allows_specific_federated_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="SpecificFederatedRole",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": (
                                "arn:aws:iam::123456789012:"
                                "saml-provider/Example"
                            )
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


def test_insecure_trust_policy_allows_restricted_service_principal():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="EC2Role",
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


def test_insecure_trust_policy_ignores_deny_statement():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="DenyTrustRole",
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


def test_insecure_trust_policy_without_document_has_no_finding():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="MissingTrustPolicy",
        attributes={},
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert findings == []


def test_insecure_trust_policy_accepts_single_statement_dict():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="SingleStatementTrustPolicy",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                },
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-004"
    assert findings[0].severity == Severity.HIGH


def test_insecure_trust_policy_ignores_non_assume_role_action():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="NonAssumeRoleTrustPolicy",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:GetCallerIdentity",
                    }
                ],
            }
        },
        source="fixture",
    )

    findings = check_insecure_trust_policy(resource)

    assert findings == []

def test_wildcard_permissions_detect_wildcard_resource_in_list():

    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="ListWildcardResourcePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                        ],
                        "Resource": [
                            "arn:aws:s3:::company-data/*",
                            "*",
                        ],
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

def test_wildcard_permissions_detect_wildcard_action_with_specific_resource():

    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="WildcardActionSpecificResourcePolicy",
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
    )

    findings = check_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-002"
    assert findings[0].severity == Severity.HIGH