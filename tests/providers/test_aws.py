from unittest.mock import Mock

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def test_aws_provider_discovers_s3_buckets():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "company-data",
            },
            {
                "Name": "company-logs",
            },
        ]
    }

    provider = AWSProvider(
        s3_client=s3_client,
    )

    resources = provider.discover_s3_buckets()

    assert len(resources) == 2

    assert resources[0].resource_type == "aws_s3_bucket"
    assert resources[0].resource_id == "company-data"
    assert resources[0].source == "aws"

    assert resources[1].resource_type == "aws_s3_bucket"
    assert resources[1].resource_id == "company-logs"


def test_aws_provider_returns_resource_objects():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "secure-data",
            }
        ]
    }

    provider = AWSProvider(
        s3_client=s3_client,
    )

    resources = provider.discover_s3_buckets()

    assert isinstance(resources[0], Resource)


def test_aws_provider_preserves_bucket_attributes():
    s3_client = Mock()

    bucket = {
        "Name": "company-data",
        "CreationDate": "2026-01-01T00:00:00Z",
    }

    s3_client.list_buckets.return_value = {
        "Buckets": [bucket]
    }

    provider = AWSProvider(
        s3_client=s3_client,
    )

    resources = provider.discover_s3_buckets()

    assert resources[0].attributes["Name"] == "company-data"
    assert (
        resources[0].attributes["CreationDate"]
        == "2026-01-01T00:00:00Z"
    )


def test_aws_provider_uses_supplied_region():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "company-data",
            }
        ]
    }

    provider = AWSProvider(
        s3_client=s3_client,
        region="eu-west-2",
    )

    resources = provider.discover_s3_buckets()

    assert resources[0].region == "eu-west-2"