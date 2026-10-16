from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.s3_rules import check_s3_account_block_public_access


def client_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


def provider_with_clients(s3control, sts=None):
    sts = sts or Mock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    return AWSProvider.__new__(AWSProvider), s3control, sts


def test_account_public_access_block_fully_enabled_is_not_flagged():
    s3control = Mock()
    s3control.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    provider = AWSProvider.__new__(AWSProvider)
    provider.sts_client = Mock()
    provider.sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
    provider.s3control_client = s3control

    resource = provider.discover_s3_account_public_access_block()[0]
    assert resource.account_id == "123456789012"
    assert resource.region is None
    assert check_s3_account_block_public_access(resource) == []


def test_missing_account_public_access_block_is_reported():
    s3control = Mock()
    s3control.get_public_access_block.side_effect = client_error(
        "NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock"
    )
    provider = AWSProvider.__new__(AWSProvider)
    provider.sts_client = Mock()
    provider.sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
    provider.s3control_client = s3control

    resource = provider.discover_s3_account_public_access_block()[0]
    findings = check_s3_account_block_public_access(resource)
    assert resource.attributes["configured"] is False
    assert len(findings) == 1
    assert findings[0].check_id == "S3-017"
    assert "NOT_CONFIGURED" in findings[0].evidence


def test_partial_account_public_access_block_reports_only_disabled_flags():
    resource = Resource(
        resource_type="aws_s3_account_public_access_block",
        resource_id="123456789012",
        attributes={
            "configured": True,
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": False,
            "restrict_public_buckets": True,
        },
        source="aws",
    )
    findings = check_s3_account_block_public_access(resource)
    assert len(findings) == 1
    assert "block_public_policy" in findings[0].evidence
    assert "block_public_acls" not in findings[0].evidence


def test_unknown_account_public_access_block_is_not_treated_as_safe_or_insecure():
    resource = Resource(
        resource_type="aws_s3_account_public_access_block",
        resource_id="123456789012",
        attributes={"configured": None},
        source="aws",
    )
    assert check_s3_account_block_public_access(resource) == []


def test_account_public_access_block_permission_error_propagates():
    s3control = Mock()
    s3control.get_public_access_block.side_effect = client_error("AccessDenied", "GetPublicAccessBlock")
    provider = AWSProvider.__new__(AWSProvider)
    provider.sts_client = Mock()
    provider.sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
    provider.s3control_client = s3control
    with pytest.raises(ClientError):
        provider.discover_s3_account_public_access_block()


def test_account_public_access_block_rule_is_registered():
    from aws_security_scanner.rules.registry import get_all_rules

    assert check_s3_account_block_public_access in get_all_rules()
