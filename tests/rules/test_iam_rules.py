from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.iam_rules import (
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
    check_overly_permissive_policy,
    check_wildcard_permissions,
    check_user_without_mfa,
    check_active_access_key,
    check_old_access_key,
    check_stale_password_user,
    check_inline_wildcard_permissions,
    check_privilege_escalation_permissions,
    check_sensitive_iam_action,
    check_broad_trust_relationship,
    check_root_account_without_mfa,
    check_root_account_access_keys,
    check_unused_access_key,
    check_never_used_console_password,
    check_unused_iam_role,
)


# IAM-001 — Unrestricted IAM Permissions

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

def test_wildcard_permissions_detect_broad_not_action():

    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="BroadNotActionPolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": "iam:DeleteUser",
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

def test_wildcard_permissions_detect_broad_not_action_with_specific_resource():

    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="BroadNotActionSpecificResourcePolicy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": "iam:DeleteUser",
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

def test_user_without_mfa_generates_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-without-mfa",
        attributes={
            "mfa_enabled": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_user_without_mfa(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-005"
    assert findings[0].severity == Severity.HIGH

def test_user_with_mfa_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-mfa",
        attributes={
            "mfa_enabled": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_user_without_mfa(resource)

    assert findings == []

def test_active_access_key_generates_informational_observation():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-active-key",
        attributes={
            "access_keys": [
                {
                    "access_key_id": "AKIAEXAMPLE",
                    "status": "Active",
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_active_access_key(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-006"
    assert findings[0].severity == Severity.INFO
    assert "not inherently insecure" in findings[0].description
    assert "minimum permissions" in findings[0].remediation

def test_inactive_access_key_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-inactive-key",
        attributes={
            "access_keys": [
                {
                    "access_key_id": "AKIAINACTIVE",
                    "status": "Inactive",
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_active_access_key(resource)

    assert findings == []
    
def test_old_access_key_generates_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-old-key",
        attributes={
            "access_keys": [
                {
                    "access_key_id": "AKIAOLDKEY",
                    "status": "Active",
                    "created_at": "2025-01-01",
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_old_access_key(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-007"
    assert findings[0].severity == Severity.HIGH

def test_recent_access_key_does_not_generate_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-recent-key",
        attributes={
            "access_keys": [
                {
                    "access_key_id": "AKIARECENTKEY",
                    "status": "Active",
                    "created_at": "2026-09-01",
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_old_access_key(resource)

    assert findings == []

def test_stale_password_enabled_user_generates_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="stale-password-user",
        attributes={
            "password_enabled": True,
            "password_last_used": "2025-01-01",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_stale_password_user(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-008"
    assert findings[0].severity == Severity.MEDIUM

def test_inline_wildcard_permissions_generate_finding():
    resource = Resource(
        resource_type="aws_iam_user",
        resource_id="user-with-inline-wildcard",
        attributes={
            "inline_policies": [
                {
                    "policy_document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ]
                    }
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_inline_wildcard_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-009"
    assert findings[0].severity == Severity.HIGH


def test_privilege_escalation_permissions_generate_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="privilege-escalation-policy",
        attributes={
            "policy_document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreatePolicyVersion",
                        "Resource": "*",
                    }
                ]
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_privilege_escalation_permissions(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-010"
    assert findings[0].severity == Severity.HIGH


def test_sensitive_iam_action_on_wildcard_resource_generates_finding():
    resource = Resource(
        resource_type="aws_iam_policy",
        resource_id="sensitive-wildcard-policy",
        attributes={
            "policy_document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:CreateRole",
                        "Resource": "*",
                    }
                ]
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_sensitive_iam_action(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-011"
    assert findings[0].severity == Severity.HIGH


def test_broad_trust_relationship_generates_finding():
    resource = Resource(
        resource_type="aws_iam_role",
        resource_id="broad-trust-role",
        attributes={
            "assume_role_policy_document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::123456789012:root"
                        },
                        "Action": "sts:AssumeRole",
                    }
                ]
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_broad_trust_relationship(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-012"
    assert findings[0].severity == Severity.HIGH

def test_root_account_without_mfa_detected():
    resource = Resource("aws_iam_account", "root", {"root_mfa_enabled": False}, "fixture")
    findings = check_root_account_without_mfa(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-013"
    assert findings[0].severity == Severity.CRITICAL


def test_root_account_access_key_detected():
    resource = Resource("aws_iam_account", "root", {
        "root_access_key_1_active": False, "root_access_key_2_active": True
    }, "fixture")
    findings = check_root_account_access_keys(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-014"


def test_unused_active_access_key_detected():
    from datetime import datetime, timedelta, timezone
    old_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    resource = Resource("aws_iam_user", "old-key-user", {"access_keys": [{
        "access_key_id": "AKIAOLD", "status": "Active",
        "created_at": old_date, "last_used_date": None
    }]}, "fixture")
    findings = check_unused_access_key(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-015"


def test_never_used_old_console_password_detected():
    from datetime import datetime, timedelta, timezone
    old_date = (datetime.now(timezone.utc) - timedelta(days=150)).isoformat()
    resource = Resource("aws_iam_user", "unused-console-user", {
        "password_enabled": True, "password_last_used": None,
        "password_last_changed": old_date
    }, "fixture")
    findings = check_never_used_console_password(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-016"


def test_unused_iam_role_detected():
    from datetime import datetime, timedelta, timezone
    old_date = (datetime.now(timezone.utc) - timedelta(days=180)).isoformat()
    resource = Resource("aws_iam_role", "stale-role", {
        "create_date": old_date, "last_used_date": None
    }, "fixture")
    findings = check_unused_iam_role(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-017"
