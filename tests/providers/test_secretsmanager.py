from unittest.mock import call, Mock

from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def no_resource_policy():
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException", "Message": "No resource policy"}},
        "GetResourcePolicy",
    )


def test_secrets_manager_discovery_normalises_metadata_and_policy():
    client = Mock()
    client.list_secrets.return_value = {
        "SecretList": [{
            "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:customer-api-token-abc",
            "Name": "customer-api-token",
        }]
    }
    client.describe_secret.return_value = {
        "ARN": "arn:aws:secretsmanager:eu-west-2:123456789012:secret:customer-api-token-abc",
        "Name": "customer-api-token",
        "RotationEnabled": False,
        "KmsKeyId": "alias/customer-secrets",
    }
    client.get_resource_policy.return_value = {
        "ResourcePolicy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}'
    }

    provider = AWSProvider(secretsmanager_client=client, region="eu-west-2")
    resources = provider.discover_secrets_manager_secrets()

    assert len(resources) == 1
    resource = resources[0]
    assert isinstance(resource, Resource)
    assert resource.resource_type == "aws_secretsmanager_secret"
    assert resource.resource_id == "customer-api-token"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"
    assert resource.attributes["rotation_enabled"] is False
    assert resource.attributes["kms_key_id"] == "alias/customer-secrets"
    assert resource.attributes["resource_policy"]["Statement"][0]["Principal"] == "*"
    client.describe_secret.assert_called_once_with(
        SecretId="arn:aws:secretsmanager:eu-west-2:123456789012:secret:customer-api-token-abc"
    )
    client.get_resource_policy.assert_called_once_with(
        SecretId="arn:aws:secretsmanager:eu-west-2:123456789012:secret:customer-api-token-abc"
    )
    assert "SecretString" not in resource.attributes
    assert "SecretBinary" not in resource.attributes


def test_secrets_manager_discovery_handles_pagination_and_missing_policy():
    client = Mock()
    client.list_secrets.side_effect = [
        {"SecretList": [{"ARN": "arn:one", "Name": "one"}], "NextToken": "page-2"},
        {"SecretList": [{"ARN": "arn:two", "Name": "two"}]},
    ]
    client.describe_secret.side_effect = [
        {"Name": "one", "RotationEnabled": True},
        {"Name": "two"},
    ]
    client.get_resource_policy.side_effect = no_resource_policy()

    provider = AWSProvider(secretsmanager_client=client, region="eu-west-2")
    resources = provider.discover_secrets_manager_secrets()

    assert [resource.resource_id for resource in resources] == ["one", "two"]
    assert client.list_secrets.call_args_list == [
        call(),
        call(NextToken="page-2"),
    ]
    assert all(resource.attributes["resource_policy"] is None for resource in resources)
    assert resources[0].attributes["rotation_enabled"] is True
    assert resources[1].attributes["rotation_enabled"] is None


def test_secrets_manager_discovery_does_not_swallow_unexpected_policy_errors():
    client = Mock()
    client.list_secrets.return_value = {"SecretList": [{"Name": "one"}]}
    client.describe_secret.return_value = {"Name": "one"}
    client.get_resource_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
        "GetResourcePolicy",
    )

    provider = AWSProvider(secretsmanager_client=client, region="eu-west-2")
    import pytest
    with pytest.raises(ClientError):
        provider.discover_secrets_manager_secrets()
