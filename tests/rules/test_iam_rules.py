from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.iam_rules import check_overly_permissive_policy


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