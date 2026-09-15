from unittest.mock import Mock

from botocore.exceptions import ClientError

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

def test_aws_provider_detects_s3_encryption():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "encrypted-data",
            }
        ]
    }

    s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ]
        }
    }

    provider = AWSProvider(
        s3_client=s3_client,
    )

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["encryption"] is True

def test_aws_provider_detects_s3_encryption_disabled():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "unencrypted-data",
            }
        ]
    }

    s3_client.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": (
                    "The bucket does not have a default "
                    "encryption configuration."
                ),
            }
        },
        "GetBucketEncryption",
    )

    provider = AWSProvider(
        s3_client=s3_client,
    )

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["encryption"] is False

def test_aws_provider_detects_s3_versioning():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "versioned-data"}
        ]
    }

    s3_client.get_bucket_versioning.return_value = {
        "Status": "Enabled"
    }

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["versioning"] is True

def test_aws_provider_detects_s3_versioning_disabled():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "non-versioned-data"}
        ]
    }

    s3_client.get_bucket_versioning.return_value = {}

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["versioning"] is False

def test_aws_provider_detects_s3_block_public_access():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "protected-data"}
        ]
    }

    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    }

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["block_public_access"] is True

def test_aws_provider_detects_s3_block_public_access_disabled():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "unprotected-data"}
        ]
    }

    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    }

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["block_public_access"] is False

def test_aws_provider_detects_s3_logging():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "logged-data"}
        ]
    }

    s3_client.get_bucket_logging.return_value = {
        "LoggingEnabled": {
            "TargetBucket": "s3-access-logs"
        }
    }

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["logging"] is True

def test_aws_provider_detects_s3_logging_disabled():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "unlogged-data"}
        ]
    }

    s3_client.get_bucket_logging.return_value = {}

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["logging"] is False

def test_aws_provider_discovers_s3_bucket_policy():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "policy-data"}
        ]
    }

    s3_client.get_bucket_policy.return_value = {
        "Policy": (
            '{"Version":"2012-10-17",'
            '"Statement":['
            '{"Effect":"Allow",'
            '"Principal":"*",'
            '"Action":"s3:GetObject",'
            '"Resource":"arn:aws:s3:::policy-data/*"}'
            ']}'
        )
    }

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["bucket_policy"] == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::policy-data/*",
            }
        ],
    }

def test_aws_provider_detects_s3_bucket_without_policy():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "no-policy-data"}
        ]
    }

    s3_client.get_bucket_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchBucketPolicy",
                "Message": "The bucket does not have a policy.",
            }
        },
        "GetBucketPolicy",
    )

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1
    assert resources[0].attributes["bucket_policy"] is None

def test_aws_provider_resource_works_with_s3_encryption_rule():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "unencrypted-data"}
        ]
    }

    s3_client.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": (
                    "ServerSideEncryptionConfigurationNotFoundError"
                ),
                "Message": (
                    "The bucket does not have a default "
                    "encryption configuration."
                ),
            }
        },
        "GetBucketEncryption",
    )

    s3_client.get_bucket_versioning.return_value = {}

    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        }
    }

    s3_client.get_bucket_logging.return_value = {}

    s3_client.get_bucket_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchBucketPolicy",
                "Message": "The bucket does not have a policy.",
            }
        },
        "GetBucketPolicy",
    )

    provider = AWSProvider(s3_client=s3_client)

    resources = provider.discover_s3_buckets()

    assert len(resources) == 1

    resource = resources[0]

    assert resource.attributes["encryption"] is False