from unittest.mock import Mock

from botocore.exceptions import ClientError

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.registry import get_all_rules


def test_aws_s3_resources_are_scanned_by_rule_engine():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {
                "Name": "unencrypted-public-bucket",
            }
        ]
    }

    s3_client.get_bucket_encryption.side_effect = ClientError(
    {
        "Error": {
            "Code": "ServerSideEncryptionConfigurationNotFoundError",
            "Message": "No encryption configured.",
        }
    },
    "GetBucketEncryption",
)

    s3_client.get_bucket_versioning.return_value = {}

    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
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

    provider = AWSProvider(
        s3_client=s3_client,
        region="eu-west-2",
    )

    resources = provider.discover_s3_buckets()

    engine = RuleEngine(get_all_rules())

    findings = engine.scan(resources)

    check_ids = {finding.check_id for finding in findings}

    assert "S3-002" in check_ids
    assert "S3-003" in check_ids
    assert "S3-004" in check_ids
    assert "S3-005" in check_ids