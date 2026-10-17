from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.kms_rules import (
    check_kms_key_pending_deletion,
    check_kms_key_rotation,
    check_kms_key_policy_wildcard_access,
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



def test_kms_wildcard_principal_and_actions_generates_critical_finding():
    resource = make_key(
        key_policy={
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:*",
                "Resource": "*",
            }],
        }
    )

    findings = check_kms_key_policy_wildcard_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "KMS-003"
    assert findings[0].severity == Severity.CRITICAL


def test_kms_wildcard_key_policy_with_condition_is_not_flagged():
    resource = make_key(
        key_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["kms:*"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
            }]
        }
    )

    assert check_kms_key_policy_wildcard_access(resource) == []


def test_kms_specific_principal_is_not_flagged():
    resource = make_key(
        key_policy={
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/app"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            }]
        }
    )

    assert check_kms_key_policy_wildcard_access(resource) == []


def test_kms_grant_delegation_generates_review_finding():
    from aws_security_scanner.rules.kms_rules import check_kms_broad_grants
    findings = check_kms_broad_grants(make_key(grant_discovery="success", grants=[
        {"GrantId": "grant-1", "GranteePrincipal": "arn:aws:iam::123456789012:role/app", "Operations": ["Decrypt", "CreateGrant"]}
    ]))
    assert len(findings) == 1
    assert findings[0].check_id == "KMS-005"
    assert "CreateGrant" in findings[0].evidence

def test_kms_narrow_grant_and_unknown_state_are_not_flagged():
    from aws_security_scanner.rules.kms_rules import check_kms_broad_grants
    assert check_kms_broad_grants(make_key(grant_discovery="success", grants=[{"Operations": ["Decrypt"]}])) == []
    assert check_kms_broad_grants(make_key(grant_discovery="unknown", grants=[])) == []
