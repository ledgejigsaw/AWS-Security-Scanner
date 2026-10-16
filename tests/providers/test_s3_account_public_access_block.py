from unittest.mock import Mock

from aws_security_scanner.providers.aws import AWSProvider


def test_s3_discovery_includes_account_level_public_access_block():
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = Mock()
    provider.sts_client = Mock()
    provider.s3control_client = Mock()
    provider.sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
    provider.s3control_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }
    }

    resources = provider.discover_s3_account_public_access_block()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_s3_account_public_access_block"
    assert resources[0].attributes["block_public_policy"] is False
    provider.s3control_client.get_public_access_block.assert_called_once_with(
        AccountId="123456789012"
    )
