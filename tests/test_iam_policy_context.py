from unittest.mock import Mock

from botocore.exceptions import ClientError

from aws_security_scanner.iam_policy_context import collect_iam_policy_context


def test_collects_role_trust_boundary_and_attached_policy_analysis():
    iam = Mock()
    iam.list_users.return_value = {"Users": []}
    iam.list_groups.return_value = {"Groups": []}
    iam.list_roles.return_value = {
        "Roles": [{
            "RoleName": "app-role",
            "Arn": "arn:aws:iam::123456789012:role/app-role",
            "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/boundary"},
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
            },
        }]
    }
    iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "app-policy", "PolicyArn": "arn:aws:iam::123456789012:policy/app-policy"}]
    }
    iam.list_role_policies.return_value = {"PolicyNames": []}
    iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v3"}}
    iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}
    }

    result = collect_iam_policy_context(iam)
    role = result["entities"][0]
    assert result["status"] == "complete"
    assert role["permissions_boundary_present"] is True
    assert role["trust_policy"]["statements"][0]["status"] == "broad_or_high_risk_allow_review"
    assert role["attached_policies"][0]["analysis"]["statements"][0]["flags"]


def test_denied_policy_listing_is_partial_not_empty_success():
    iam = Mock()
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "sensitive"}}, "ListRoles")
    iam.list_users.return_value = {"Users": []}
    iam.list_groups.return_value = {"Groups": []}
    iam.list_roles.side_effect = denied

    result = collect_iam_policy_context(iam)
    assert result["status"] == "partial"
    assert result["entities"] == []
    assert result["failures"] == [{
        "entity_type": "role", "operation": "list_roles", "outcome": "access_denied"
    }]
    assert "sensitive" not in str(result)


def test_inline_policy_access_denied_is_not_reported_as_no_policy():
    iam = Mock()
    iam.list_users.return_value = {"Users": [{"UserName": "analyst"}]}
    iam.list_groups.return_value = {"Groups": []}
    iam.list_roles.return_value = {"Roles": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_user_policies.return_value = {"PolicyNames": ["inline-policy"]}
    iam.get_user_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "private"}}, "GetUserPolicy"
    )

    result = collect_iam_policy_context(iam)
    user = result["entities"][0]
    assert result["status"] == "partial"
    assert user["inline_policies"][0]["status"] == "access_denied"
    assert "private" not in str(result)
