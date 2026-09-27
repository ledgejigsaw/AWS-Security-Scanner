from unittest.mock import Mock, call

from botocore.exceptions import ClientError
import pytest

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.rules.iam_rules import (
    check_insecure_trust_policy,
)


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

def test_aws_provider_handles_s3_versioning_error():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "versioning-error"}
        ]
    }

    s3_client.get_bucket_versioning.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied.",
            }
        },
        "GetBucketVersioning",
    )

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

def test_aws_provider_discovers_iam_policies():
    iam_client = Mock()

    iam_client.list_policies.return_value = {
        "Policies": [
            {
                "PolicyName": "AdminPolicy",
                "Arn": "arn:aws:iam::123456789012:policy/AdminPolicy",
                "DefaultVersionId": "v1",
            }
        ]
    }

    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        }
    }

    provider = AWSProvider(
        iam_client=iam_client,
    )

    resources = provider.discover_iam_policies()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_iam_policy"
    assert resources[0].resource_id == "AdminPolicy"
    assert resources[0].source == "aws"
    assert resources[0].attributes["policy_document"]["Statement"][0][
        "Action"
    ] == "*"

def test_aws_provider_uses_default_iam_policy_version():
    iam_client = Mock()

    policy_arn = (
        "arn:aws:iam::123456789012:policy/AdminPolicy"
    )

    iam_client.list_policies.return_value = {
        "Policies": [
            {
                "PolicyName": "AdminPolicy",
                "Arn": policy_arn,
                "DefaultVersionId": "v3",
            }
        ]
    }

    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Version": "2012-10-17",
                "Statement": [],
            }
        }
    }

    provider = AWSProvider(
        iam_client=iam_client,
    )

    provider.discover_iam_policies()

    iam_client.get_policy_version.assert_called_once_with(
        PolicyArn=policy_arn,
        VersionId="v3",
    )

def test_aws_provider_discovers_iam_roles():
    iam_client = Mock()

    iam_client.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "InsecureRole",
                "Arn": "arn:aws:iam::123456789012:role/InsecureRole",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "*"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            }
        ]
    }

    provider = AWSProvider(
        iam_client=iam_client,
    )

    resources = provider.discover_iam_roles()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_iam_role"
    assert resources[0].resource_id == "InsecureRole"
    assert resources[0].source == "aws"

    policy = resources[0].attributes[
        "assume_role_policy_document"
    ]

    assert policy["Statement"][0]["Principal"]["AWS"] == "*"

def test_aws_iam_role_discovery_integrates_with_iam_004():
    iam_client = Mock()

    iam_client.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "InsecureRole",
                "Arn": "arn:aws:iam::123456789012:role/InsecureRole",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "*"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            }
        ]
    }

    provider = AWSProvider(
        iam_client=iam_client,
    )

    resources = provider.discover_iam_roles()

    engine = RuleEngine(
        [check_insecure_trust_policy],
    )

    findings = engine.scan(resources)

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-004"
    assert findings[0].resource == "InsecureRole"

def test_aws_provider_discovers_iam_policies_from_multiple_pages():
    iam_client = Mock()

    iam_client.list_policies.side_effect = [
        {
            "Policies": [
                {
                    "PolicyName": "FirstPolicy",
                    "Arn": "arn:aws:iam::123456789012:policy/FirstPolicy",
                    "DefaultVersionId": "v1",
                }
            ],
            "IsTruncated": True,
            "Marker": "next-page",
        },
        {
            "Policies": [
                {
                    "PolicyName": "SecondPolicy",
                    "Arn": "arn:aws:iam::123456789012:policy/SecondPolicy",
                    "DefaultVersionId": "v1",
                }
            ],
            "IsTruncated": False,
        },
    ]

    iam_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Version": "2012-10-17",
                "Statement": [],
            }
        }
    }

    provider = AWSProvider(iam_client=iam_client)

    resources = provider.discover_iam_policies()

    assert len(resources) == 2
    assert resources[0].resource_id == "FirstPolicy"
    assert resources[1].resource_id == "SecondPolicy"

    iam_client.list_policies.assert_any_call(
        Scope="Local",
    )
    iam_client.list_policies.assert_any_call(
        Scope="Local",
        Marker="next-page",
    )

def test_aws_provider_discovers_iam_roles_from_multiple_pages():
    iam_client = Mock()

    iam_client.list_roles.side_effect = [
        {
            "Roles": [
                {
                    "RoleName": "FirstRole",
                    "AssumeRolePolicyDocument": {
                        "Statement": []
                    },
                }
            ],
            "IsTruncated": True,
            "Marker": "next-page",
        },
        {
            "Roles": [
                {
                    "RoleName": "SecondRole",
                    "AssumeRolePolicyDocument": {
                        "Statement": []
                    },
                }
            ],
            "IsTruncated": False,
        },
    ]

    provider = AWSProvider(
        s3_client=Mock(),
        iam_client=iam_client,
        region="eu-west-2",
    )

    resources = provider.discover_iam_roles()

    assert len(resources) == 2

    assert resources[0].resource_id == "FirstRole"
    assert resources[1].resource_id == "SecondRole"

    assert iam_client.list_roles.call_args_list == [
        call(),
        call(Marker="next-page"),
    ]


def test_aws_provider_raises_s3_encryption_access_denied():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "restricted-data"}
        ]
    }

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied.",
            }
        },
        "GetBucketEncryption",
    )

    s3_client.get_bucket_encryption.side_effect = error

    provider = AWSProvider(s3_client=s3_client)

    with pytest.raises(ClientError, match="AccessDenied"):
        provider.discover_s3_buckets()

def test_aws_provider_raises_s3_public_access_access_denied():
    s3_client = Mock()

    s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "restricted-data"}
        ]
    }

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied.",
            }
        },
        "GetPublicAccessBlock",
    )

    s3_client.get_public_access_block.side_effect = error

    provider = AWSProvider(s3_client=s3_client)

    with pytest.raises(ClientError, match="AccessDenied"):
        provider.discover_s3_buckets()

def test_discover_ec2_instances():
    class MockEC2Client:
        def describe_instances(self):
            return {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-1234567890abcdef0",
                                "InstanceType": "t3.micro",
                                "State": {
                                    "Name": "running",
                                },
                                "PublicIpAddress": "203.0.113.10",
                                "PrivateIpAddress": "10.0.1.25",
                                "SubnetId": "subnet-123456",
                                "VpcId": "vpc-123456",
                                "MetadataOptions": {
                                    "HttpTokens": "optional",
                                },
                                "SecurityGroups": [
                                    {
                                        "GroupId": "sg-123456",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }

    provider = AWSProvider(
        ec2_client=MockEC2Client(),
        region="eu-west-2",
    )

    resources = provider.discover_ec2_instances()

    assert len(resources) == 1

    resource = resources[0]

    assert resource.resource_type == "aws_instance"
    assert resource.resource_id == "i-1234567890abcdef0"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"

    assert resource.attributes["instance_type"] == "t3.micro"
    assert resource.attributes["state"] == "running"
    assert resource.attributes["public_ip_address"] == "203.0.113.10"
    assert resource.attributes["private_ip_address"] == "10.0.1.25"
    assert resource.attributes["subnet_id"] == "subnet-123456"
    assert resource.attributes["vpc_id"] == "vpc-123456"

    assert resource.attributes["metadata_options"]["http_tokens"] == "optional"

    assert resource.attributes["security_group_ids"] == [
        "sg-123456"
    ]

def test_discover_security_groups():
    class MockEC2Client:
        def describe_security_groups(self):
            return {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123456",
                        "GroupName": "web-server",
                        "VpcId": "vpc-123456",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0",
                                    }
                                ],
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "FromPort": -1,
                                "ToPort": -1,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0",
                                    }
                                ],
                                "Ipv6Ranges": [
                                    {
                                        "CidrIpv6": "::/0",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }

    provider = AWSProvider(
        ec2_client=MockEC2Client(),
        region="eu-west-2",
    )

    resources = provider.discover_security_groups()

    assert len(resources) == 1

    resource = resources[0]

    assert resource.resource_type == "aws_security_group"
    assert resource.resource_id == "sg-123456"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"

    assert resource.attributes["group_name"] == "web-server"
    assert resource.attributes["vpc_id"] == "vpc-123456"

    assert resource.attributes["ingress_rules"] == [
        {
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr": "0.0.0.0/0",
        }
    ]

    assert resource.attributes["egress_rules"] == [
        {
            "protocol": "-1",
            "from_port": -1,
            "to_port": -1,
            "cidr": "0.0.0.0/0",
        },
        {
            "protocol": "-1",
            "from_port": -1,
            "to_port": -1,
            "cidr": "::/0",
        },
    ]