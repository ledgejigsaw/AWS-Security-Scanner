from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.s3_rules import check_cross_account_bucket_policy


OWNER = "111111111111"
EXTERNAL = "222222222222"


def bucket(policy, *, account_id=OWNER, attributes=None):
    attrs = {
        "bucket_name": "example-bucket",
        "bucket_policy": policy,
    }
    attrs.update(attributes or {})
    return Resource(
        resource_type="aws_s3_bucket",
        resource_id="example-bucket",
        attributes=attrs,
        source="fixture",
        region="eu-west-2",
        account_id=account_id,
    )


def statement(**overrides):
    value = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::example-bucket/*",
    }
    value.update(overrides)
    return value


def test_external_account_allow_is_reported_as_informational_review_signal():
    resource = bucket({
        "Version": "2012-10-17",
        "Statement": [statement(
            Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
        )],
    })

    [finding] = check_cross_account_bucket_policy(resource)

    assert finding.check_id == "S3-015"
    assert finding.severity is Severity.INFO
    assert finding.account_id == OWNER
    assert f"external_principal_accounts={EXTERNAL}" in finding.evidence
    assert "condition_present=true" in finding.evidence
    assert "effective access not evaluated" in finding.evidence
    assert "Principal=" not in finding.evidence


def test_same_account_principal_does_not_trigger_cross_account_signal():
    resource = bucket({
        "Statement": [statement(
            Principal={"AWS": f"arn:aws:iam::{OWNER}:root"}
        )]
    })

    assert check_cross_account_bucket_policy(resource) == []


def test_unknown_bucket_owner_account_does_not_guess_external_access():
    resource = bucket({
        "Statement": [statement()]
    }, account_id=None)

    assert check_cross_account_bucket_policy(resource) == []


def test_deny_statement_does_not_trigger_cross_account_signal():
    resource = bucket({
        "Statement": [statement(Effect="Deny")]
    })

    assert check_cross_account_bucket_policy(resource) == []


def test_non_s3_actions_do_not_trigger_cross_account_signal():
    resource = bucket({
        "Statement": [statement(Action=["kms:Decrypt"])]
    })

    assert check_cross_account_bucket_policy(resource) == []


def test_unrelated_or_unknown_resource_scope_does_not_trigger_signal():
    unrelated = bucket({
        "Statement": [statement(Resource="arn:aws:s3:::other-bucket/*")]
    })
    unknown = bucket({
        "Statement": [statement(Resource=None)]
    })

    assert check_cross_account_bucket_policy(unrelated) == []
    assert check_cross_account_bucket_policy(unknown) == []


def test_wildcard_principal_is_left_to_existing_public_access_checks():
    resource = bucket({
        "Statement": [statement(Principal="*")]
    })

    assert check_cross_account_bucket_policy(resource) == []


def test_single_statement_policy_document_is_supported():
    resource = bucket({"Statement": statement()})

    [finding] = check_cross_account_bucket_policy(resource)

    assert finding.check_id == "S3-015"
