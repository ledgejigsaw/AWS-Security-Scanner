from unittest.mock import Mock, call

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def test_ecr_discovery_normalises_repository_security_metadata():
    client = Mock()
    client.describe_repositories.return_value = {
        "repositories": [{
            "repositoryArn": "arn:aws:ecr:eu-west-2:123456789012:repository/payments",
            "repositoryName": "payments",
            "repositoryUri": "123456789012.dkr.ecr.eu-west-2.amazonaws.com/payments",
            "imageTagMutability": "MUTABLE",
            "imageScanningConfiguration": {"scanOnPush": False},
            "encryptionConfiguration": {"encryptionType": "KMS", "kmsKey": "alias/ecr"},
        }]
    }

    provider = AWSProvider(ecr_client=client, region="eu-west-2")
    resources = provider.discover_ecr_repositories()

    assert len(resources) == 1
    resource = resources[0]
    assert isinstance(resource, Resource)
    assert resource.resource_type == "aws_ecr_repository"
    assert resource.resource_id == "payments"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"
    assert resource.attributes["uri"].endswith("/payments")
    assert resource.attributes["image_tag_mutability"] == "MUTABLE"
    assert resource.attributes["scan_on_push"] is False
    assert resource.attributes["encryption_type"] == "KMS"
    assert resource.attributes["kms_key"] == "alias/ecr"
    client.describe_repositories.assert_called_once_with()


def test_ecr_discovery_handles_pagination_and_empty_repositories():
    client = Mock()
    client.describe_repositories.side_effect = [
        {"repositories": [{"repositoryName": "first"}], "nextToken": "page-2"},
        {"repositories": [{"repositoryName": "second"}]},
    ]

    provider = AWSProvider(ecr_client=client, region="eu-west-2")
    resources = provider.discover_ecr_repositories()

    assert [resource.resource_id for resource in resources] == ["first", "second"]
    assert client.describe_repositories.call_args_list == [
        call(),
        call(nextToken="page-2"),
    ]

    client.describe_repositories.return_value = {"repositories": []}
    client.describe_repositories.side_effect = None
    assert provider.discover_ecr_repositories() == []


def test_ecr_discovery_preserves_unknown_optional_configuration():
    client = Mock()
    client.describe_repositories.return_value = {
        "repositories": [{"repositoryName": "minimal"}]
    }

    resource = AWSProvider(
        ecr_client=client, region="eu-west-2"
    ).discover_ecr_repositories()[0]

    assert resource.attributes["image_tag_mutability"] is None
    assert resource.attributes["scan_on_push"] is None
    assert resource.attributes["encryption_type"] is None
    assert "image_layers" not in resource.attributes
    assert "credentials" not in resource.attributes
