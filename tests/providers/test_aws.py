from unittest.mock import Mock, call


from botocore.exceptions import ClientError
import pytest

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import (
    AWSProvider,
    CredentialReportUnavailableError,
)

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
    assert resources[0].attributes["versioning"] is None
    
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

def test_aws_provider_discovers_vpcs():
    ec2_client = Mock()

    ec2_client.describe_vpcs.return_value = {
        "Vpcs": [
            {
                "VpcId": "vpc-security01",
                "CidrBlock": "10.0.0.0/16",
                "IsDefault": False,
            }
        ]
    }

    provider = AWSProvider(
        ec2_client=ec2_client,
    )

    resources = provider.discover_vpcs()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_vpc"
    assert resources[0].resource_id == "vpc-security01"
    assert resources[0].attributes["cidr_block"] == "10.0.0.0/16"
    assert resources[0].attributes["is_default"] is False


def test_aws_provider_discovers_subnets():
    ec2_client = Mock()

    ec2_client.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-private01",
                "VpcId": "vpc-security01",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "eu-west-2a",
                "MapPublicIpOnLaunch": False,
            }
        ]
    }

    provider = AWSProvider(
        ec2_client=ec2_client,
    )

    resources = provider.discover_subnets()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_subnet"
    assert resources[0].resource_id == "subnet-private01"
    assert resources[0].attributes["vpc_id"] == "vpc-security01"
    assert resources[0].attributes["cidr_block"] == "10.0.1.0/24"
    assert resources[0].attributes["map_public_ip_on_launch"] is False


def test_aws_provider_discovers_route_tables():
    ec2_client = Mock()

    ec2_client.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-security01",
                "VpcId": "vpc-security01",
                "Routes": [
                    {
                        "DestinationCidrBlock": "10.0.0.0/16",
                        "GatewayId": "local",
                        "State": "active",
                    }
                ],
                "Associations": [
                    {
                        "SubnetId": "subnet-private01",
                        "Main": False,
                        "RouteTableAssociationId": "rtbassoc-security01",
                    }
                ],
            }
        ]
    }

    provider = AWSProvider(
        ec2_client=ec2_client,
    )

    resources = provider.discover_route_tables()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_route_table"
    assert resources[0].resource_id == "rtb-security01"
    assert resources[0].attributes["vpc_id"] == "vpc-security01"
    assert resources[0].attributes["routes"][0]["destination_cidr"] == (
        "10.0.0.0/16"
    )
    assert resources[0].attributes["associations"][0]["subnet_id"] == (
        "subnet-private01"
    )


def test_aws_provider_discovers_network_acls():
    ec2_client = Mock()

    ec2_client.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "NetworkAclId": "acl-security01",
                "VpcId": "vpc-security01",
                "IsDefault": False,
                "Entries": [
                    {
                        "Egress": False,
                        "RuleNumber": 100,
                        "Protocol": "6",
                        "RuleAction": "allow",
                        "CidrBlock": "10.0.0.0/16",
                        "PortRange": {
                            "From": 443,
                            "To": 443,
                        },
                    }
                ],
                "Associations": [
                    {
                        "SubnetId": "subnet-private01",
                        "NetworkAclAssociationId": "aclassoc-security01",
                    }
                ],
            }
        ]
    }

    provider = AWSProvider(
        ec2_client=ec2_client,
    )

    resources = provider.discover_network_acls()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_network_acl"
    assert resources[0].resource_id == "acl-security01"
    assert resources[0].attributes["vpc_id"] == "vpc-security01"
    assert resources[0].attributes["entries"][0]["rule_action"] == "allow"
    assert resources[0].attributes["entries"][0]["from_port"] == 443
    assert resources[0].attributes["associations"][0]["subnet_id"] == (
        "subnet-private01"
    )


def test_aws_provider_discovers_flow_logs():
    ec2_client = Mock()

    ec2_client.describe_flow_logs.return_value = {
        "FlowLogs": [
            {
                "FlowLogId": "fl-security01",
                "ResourceId": "vpc-security01",
                "ResourceType": "VPC",
                "TrafficType": "ALL",
                "LogDestinationType": "cloud-watch-logs",
                "LogDestination": "arn:aws:logs:eu-west-2:123456789012:log-group:vpc-flow-logs",
                "DeliverLogsStatus": "SUCCESS",
            }
        ]
    }

    provider = AWSProvider(
        ec2_client=ec2_client,
    )

    resources = provider.discover_flow_logs()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_flow_log"
    assert resources[0].resource_id == "fl-security01"
    assert resources[0].attributes["resource_id"] == "vpc-security01"
    assert resources[0].attributes["resource_type"] == "VPC"
    assert resources[0].attributes["traffic_type"] == "ALL"
    assert resources[0].attributes["deliver_logs_status"] == "SUCCESS"

def test_aws_provider_discovers_iam_user_security_attributes():
    from datetime import datetime, timezone

    iam_client = Mock()
    iam_client.list_users.return_value = {
        "Users": [{
            "UserName": "legacy-user",
            "UserId": "AIDAEXAMPLE",
            "Arn": "arn:aws:iam::123456789012:user/legacy-user",
            "Path": "/",
        }],
        "IsTruncated": False,
    }
    iam_client.get_credential_report.return_value = {
        "Content": (
            "user,password_enabled,password_last_used\n"
            "legacy-user,true,2025-01-01T00:00:00+00:00\n"
        ).encode("utf-8")
    }
    iam_client.list_mfa_devices.return_value = {"MFADevices": []}
    iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [{
            "AccessKeyId": "AKIAEXAMPLE",
            "Status": "Active",
            "CreateDate": datetime(2025, 1, 1, tzinfo=timezone.utc),
        }]
    }
    iam_client.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {
            "LastUsedDate": datetime(2025, 2, 1, tzinfo=timezone.utc),
            "ServiceName": "s3",
            "Region": "eu-west-2",
        }
    }
    iam_client.list_user_policies.return_value = {
        "PolicyNames": ["InlineAdmin"],
        "IsTruncated": False,
    }
    iam_client.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
    }

    user = AWSProvider(iam_client=iam_client).discover_iam_users()[0]

    assert user.resource_type == "aws_iam_user"
    assert user.resource_id == "legacy-user"
    assert user.attributes["mfa_enabled"] is False
    assert user.attributes["password_enabled"] is True
    assert user.attributes["password_last_used"] == "2025-01-01T00:00:00+00:00"
    assert user.attributes["access_keys"][0]["status"] == "Active"
    assert user.attributes["access_keys"][0]["created_at"] == "2025-01-01T00:00:00+00:00"
    assert user.attributes["access_keys"][0]["last_used_service"] == "s3"
    assert user.attributes["inline_policies"][0]["policy_name"] == "InlineAdmin"


def test_aws_provider_parses_iam_credential_report():
    iam_client = Mock()
    iam_client.get_credential_report.return_value = {
        "Content": (
            "user,password_enabled,password_last_used\n"
            "alice,false,N/A\n"
            "bob,true,no_information\n"
        ).encode("utf-8")
    }

    report = AWSProvider(iam_client=iam_client).discover_iam_credential_report()

    assert report["alice"]["password_enabled"] == "false"
    assert report["bob"]["password_last_used"] == "no_information"


def test_aws_provider_generates_missing_iam_credential_report():
    iam_client = Mock()
    iam_client.get_credential_report.side_effect = ClientError(
        {"Error": {"Code": "CredentialReportNotPresent", "Message": "No report."}},
        "GetCredentialReport",
    )
    iam_client.generate_credential_report.return_value = {"State": "STARTED"}

    with pytest.raises(CredentialReportUnavailableError, match="does not exist"):
        AWSProvider(iam_client=iam_client).discover_iam_credential_report()
    iam_client.generate_credential_report.assert_called_once_with()


def test_aws_provider_discovers_iam_account_root_security():
    iam_client = Mock()
    iam_client.get_credential_report.return_value = {"Content": (
        "user,mfa_active,access_key_1_active,access_key_2_active\n"
        "<root_account>,false,true,false\n"
    ).encode("utf-8")}
    resources = AWSProvider(iam_client=iam_client).discover_iam_account()
    assert len(resources) == 1
    assert resources[0].resource_type == "aws_iam_account"
    assert resources[0].attributes["root_mfa_enabled"] is False
    assert resources[0].attributes["root_access_key_1_active"] is True
    assert resources[0].attributes["root_access_key_2_active"] is False



def test_aws_provider_paginates_s3_bucket_listing():
    s3_client = Mock()
    s3_client.list_buckets.side_effect = [
        {
            "Buckets": [{"Name": "first-bucket"}],
            "NextContinuationToken": "page-2",
        },
        {
            "Buckets": [{"Name": "second-bucket"}],
        },
    ]

    resources = AWSProvider(s3_client=s3_client).discover_s3_buckets()

    assert [resource.resource_id for resource in resources] == [
        "first-bucket",
        "second-bucket",
    ]
    s3_client.list_buckets.assert_has_calls([
        call(),
        call(ContinuationToken="page-2"),
    ])


def test_aws_provider_paginates_ec2_instance_discovery():
    ec2_client = Mock()
    ec2_client.describe_instances.side_effect = [
        {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-first",
                    "State": {"Name": "running"},
                }],
            }],
            "NextToken": "page-2",
        },
        {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-second",
                    "State": {"Name": "stopped"},
                }],
            }],
        },
    ]

    resources = AWSProvider(
        ec2_client=ec2_client,
        region="eu-west-2",
    ).discover_ec2_instances()

    assert [resource.resource_id for resource in resources] == [
        "i-first",
        "i-second",
    ]
    ec2_client.describe_instances.assert_has_calls([
        call(),
        call(NextToken="page-2"),
    ])


def test_aws_provider_rejects_truncated_response_without_token():
    ec2_client = Mock()
    ec2_client.describe_vpcs.return_value = {
        "Vpcs": [{"VpcId": "vpc-first"}],
        "IsTruncated": True,
    }

    with pytest.raises(RuntimeError, match="without a continuation token"):
        AWSProvider(ec2_client=ec2_client).discover_vpcs()


def test_aws_provider_rejects_repeated_pagination_token():
    ec2_client = Mock()
    ec2_client.describe_vpcs.side_effect = [
        {"Vpcs": [{"VpcId": "vpc-first"}], "NextToken": "same-token"},
        {"Vpcs": [{"VpcId": "vpc-second"}], "NextToken": "same-token"},
    ]

    with pytest.raises(RuntimeError, match="repeated continuation token"):
        AWSProvider(ec2_client=ec2_client).discover_vpcs()


@pytest.mark.parametrize(
    "error_code",
    ["CredentialReportNotReady", "CredentialReportExpired", "ReportInProgress"],
)
def test_aws_provider_does_not_hide_unavailable_credential_report(error_code):
    iam_client = Mock()
    iam_client.get_credential_report.side_effect = ClientError(
        {"Error": {"Code": error_code, "Message": "Report unavailable."}},
        "GetCredentialReport",
    )

    with pytest.raises(CredentialReportUnavailableError, match="unavailable"):
        AWSProvider(iam_client=iam_client).discover_iam_credential_report()


@pytest.mark.parametrize("content", [b"", b"user,password_enabled\n"])
def test_aws_provider_rejects_empty_or_incomplete_credential_report(content):
    iam_client = Mock()
    iam_client.get_credential_report.return_value = {"Content": content}

    with pytest.raises(CredentialReportUnavailableError):
        AWSProvider(iam_client=iam_client).discover_iam_credential_report()


def test_aws_provider_rejects_credential_report_without_root_account():
    iam_client = Mock()
    iam_client.get_credential_report.return_value = {
        "Content": b"user,password_enabled\nalice,true\n"
    }

    with pytest.raises(CredentialReportUnavailableError, match="root_account"):
        AWSProvider(iam_client=iam_client).discover_iam_account()


def test_aws_provider_discovers_cloudtrail_trails_and_logging_status():
    cloudtrail_client = Mock()
    cloudtrail_client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "organization-trail",
                "TrailARN": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/organization-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
                "HomeRegion": "eu-west-2",
            }
        ]
    }
    cloudtrail_client.get_trail_status.return_value = {
        "IsLogging": False,
        "LatestDeliveryError": "Access denied",
    }

    resources = AWSProvider(
        cloudtrail_client=cloudtrail_client,
        region="eu-west-2",
    ).discover_cloudtrail_trails()

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_cloudtrail_trail"
    assert resources[0].attributes["is_logging"] is False
    assert resources[0].attributes["is_multi_region_trail"] is True
    assert resources[0].attributes["latest_delivery_error"] == "Access denied"
    cloudtrail_client.get_trail_status.assert_called_once_with(
        Name="arn:aws:cloudtrail:eu-west-2:123456789012:trail/organization-trail"
    )


def test_aws_provider_paginates_cloudtrail_trail_discovery():
    cloudtrail_client = Mock()
    cloudtrail_client.describe_trails.side_effect = [
        {"trailList": [{"Name": "first", "TrailARN": "arn:first"}], "NextToken": "page-2"},
        {"trailList": [{"Name": "second", "TrailARN": "arn:second"}]},
    ]
    cloudtrail_client.get_trail_status.return_value = {"IsLogging": True}

    resources = AWSProvider(
        cloudtrail_client=cloudtrail_client,
    ).discover_cloudtrail_trails()

    assert [resource.attributes["name"] for resource in resources] == [
        "first",
        "second",
    ]
    cloudtrail_client.describe_trails.assert_has_calls([
        call(includeShadowTrails=False),
        call(includeShadowTrails=False, NextToken="page-2"),
    ])


def test_aws_provider_discovers_kms_keys_and_rotation_state():
    kms_client = Mock()
    kms_client.list_keys.side_effect = [
        {
            "Keys": [{"KeyId": "customer-key"}],
            "Truncated": True,
            "NextMarker": "page-2",
        },
        {
            "Keys": [{"KeyId": "aws-managed-key"}],
            "Truncated": False,
        },
    ]

    def describe_key(*, KeyId):
        if KeyId == "customer-key":
            return {
                "KeyMetadata": {
                    "KeyId": KeyId,
                    "Arn": "arn:aws:kms:eu-west-2:123456789012:key/customer-key",
                    "KeyManager": "CUSTOMER",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeyState": "Enabled",
                }
            }
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "Arn": "arn:aws:kms:eu-west-2:123456789012:key/aws-managed-key",
                "KeyManager": "AWS",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
            }
        }

    kms_client.describe_key.side_effect = describe_key
    kms_client.get_key_rotation_status.return_value = {
        "KeyRotationEnabled": False
    }

    resources = AWSProvider(
        kms_client=kms_client,
        region="eu-west-2",
    ).discover_kms_keys()

    assert len(resources) == 2
    assert resources[0].attributes["rotation_applicable"] is True
    assert resources[0].attributes["rotation_enabled"] is False
    assert resources[1].attributes["rotation_applicable"] is False
    assert resources[1].attributes["rotation_enabled"] is None
    kms_client.list_keys.assert_has_calls([
        call(),
        call(Marker="page-2"),
    ])
    kms_client.get_key_rotation_status.assert_called_once_with(
        KeyId="customer-key"
    )



def test_aws_provider_discovers_kms_key_policy():
    kms_client = Mock()
    kms_client.list_keys.return_value = {
        "Keys": [{"KeyId": "customer-key"}],
    }
    kms_client.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "customer-key",
            "Arn": "arn:aws:kms:eu-west-2:123456789012:key/customer-key",
            "KeyManager": "CUSTOMER",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
        }
    }
    kms_client.get_key_rotation_status.return_value = {
        "KeyRotationEnabled": True,
    }
    kms_client.list_grants.return_value = {"Grants": [], "Truncated": False}
    kms_client.get_key_policy.return_value = {
        "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*","Resource":"*"}]}'
    }

    resources = AWSProvider(kms_client=kms_client).discover_kms_keys()

    assert resources[0].attributes["key_policy"]["Statement"][0]["Principal"] == "*"
    kms_client.get_key_policy.assert_called_once_with(
        KeyId="customer-key",
        PolicyName="default",
    )


def test_aws_provider_discovers_s3_acl_ownership_and_mfa_delete():
    s3_client = Mock()
    s3_client.list_buckets.return_value = {
        "Buckets": [{"Name": "company-data"}]
    }
    s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": []}
    }
    s3_client.get_bucket_versioning.return_value = {
        "Status": "Enabled",
        "MFADelete": "Disabled",
    }
    s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3_client.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}
    s3_client.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "No policy"}},
        "GetBucketPolicy",
    )
    s3_client.get_bucket_acl.return_value = {
        "Grants": [{
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
            },
            "Permission": "READ",
        }]
    }
    s3_client.get_bucket_ownership_controls.return_value = {
        "OwnershipControls": {
            "Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]
        }
    }

    provider = AWSProvider(s3_client=s3_client)
    resource = provider.discover_s3_buckets()[0]

    assert resource.attributes["acl"]["grants"][0]["grantee"]["uri"].endswith("/AllUsers")
    assert resource.attributes["object_ownership"] == "BucketOwnerPreferred"
    assert resource.attributes["versioning_configuration"] == {
        "status": "Enabled",
        "mfa_delete": "Disabled",
    }


def test_aws_provider_keeps_extended_s3_metadata_unknown_on_access_denied():
    s3_client = Mock()
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = s3_client
    denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetBucketAcl",
    )
    s3_client.get_bucket_acl.side_effect = denied
    s3_client.get_bucket_ownership_controls.side_effect = denied
    s3_client.get_bucket_versioning.side_effect = denied

    assert provider._get_bucket_acl("company-data") is None
    assert provider._get_bucket_object_ownership("company-data") is None
    assert provider._get_bucket_versioning_configuration("company-data") is None



def test_aws_provider_discovers_s3_object_lock_configuration():
    s3_client = Mock()
    s3_client.list_buckets.return_value = {"Buckets": [{"Name": "retention-data"}]}
    s3_client.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {
                "DefaultRetention": {
                    "Mode": "GOVERNANCE",
                    "Days": 90,
                }
            },
        }
    }

    resource = AWSProvider(s3_client=s3_client).discover_s3_buckets()[0]

    assert resource.attributes["object_lock_configuration"] == {
        "status": "CONFIGURED",
        "enabled": True,
        "default_retention": {
            "mode": "GOVERNANCE",
            "days": 90,
            "years": None,
        },
    }
    s3_client.get_object_lock_configuration.assert_called_once_with(
        Bucket="retention-data"
    )


def test_aws_provider_distinguishes_missing_object_lock_from_access_denied():
    s3_client = Mock()
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = s3_client
    s3_client.get_object_lock_configuration.side_effect = ClientError(
        {
            "Error": {
                "Code": "ObjectLockConfigurationNotFoundError",
                "Message": "Object Lock is not configured",
            }
        },
        "GetObjectLockConfiguration",
    )
    assert provider._get_bucket_object_lock_configuration("no-lock") == {
        "status": "NOT_CONFIGURED",
        "enabled": False,
        "default_retention": None,
    }

    s3_client.get_object_lock_configuration.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetObjectLockConfiguration",
    )
    assert provider._get_bucket_object_lock_configuration("unknown") == {
        "status": "UNKNOWN",
        "enabled": None,
        "default_retention": None,
    }


def test_aws_provider_keeps_malformed_object_lock_response_unknown():
    s3_client = Mock()
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = s3_client
    s3_client.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {}
    }

    assert provider._get_bucket_object_lock_configuration("malformed") == {
        "status": "UNKNOWN",
        "enabled": None,
        "default_retention": None,
    }


def test_kms_grant_discovery_exposes_complete_pagination_metadata():
    kms_client = Mock()
    kms_client.list_keys.return_value = {"Keys": [{"KeyId": "key-1"}]}
    kms_client.describe_key.return_value = {"KeyMetadata": {
        "KeyId": "key-1", "Arn": "arn:aws:kms:eu-west-2:123456789012:key/key-1",
        "KeyManager": "CUSTOMER", "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": "Enabled",
    }}
    kms_client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    kms_client.get_key_policy.return_value = {"Policy": '{"Statement":[]}'}
    kms_client.list_grants.side_effect = [
        {"Grants": [{"GrantId": "g1", "Operations": ["Decrypt"]}], "Truncated": True, "NextMarker": "p2"},
        {"Grants": [{"GrantId": "g2", "Operations": ["Encrypt"]}], "Truncated": False},
    ]
    resource = AWSProvider(kms_client=kms_client).discover_kms_keys()[0]
    assert resource.attributes["grant_count"] == 2
    assert resource.attributes["grant_pages"] == 2
    assert resource.attributes["grant_pagination_complete"] is True
    assert resource.attributes["grant_discovery"] == "success"


def test_cloudtrail_advanced_selectors_count_only_explicit_data_events():
    cloudtrail = Mock()
    cloudtrail.describe_trails.return_value = {"trailList": [{
        "Name": "account-trail", "TrailARN": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/account-trail",
        "IsOrganizationTrail": False, "IsMultiRegionTrail": True,
    }]}
    cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    cloudtrail.get_event_selectors.return_value = {
        "EventSelectors": [{"IncludeManagementEvents": True, "DataResources": [
            {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::example/*"]}
        ]}],
        "AdvancedEventSelectors": [
            {"Name": "data-events", "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]},
            ]},
            {"Name": "management-only", "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Management"]}
            ]},
        ],
    }
    resource = AWSProvider(cloudtrail_client=cloudtrail, region="eu-west-2").discover_cloudtrail_trails()[0]
    assert resource.attributes["organization_trail_scope"] == "account"
    assert resource.attributes["data_event_selector_count"] == 2
    assert resource.attributes["data_event_coverage"] == "configured"


def test_cloudtrail_missing_org_metadata_remains_unknown():
    cloudtrail = Mock()
    cloudtrail.describe_trails.return_value = {"trailList": [{
        "Name": "legacy", "TrailARN": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/legacy",
    }]}
    cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    cloudtrail.get_event_selectors.return_value = {"EventSelectors": [], "AdvancedEventSelectors": []}
    resource = AWSProvider(cloudtrail_client=cloudtrail).discover_cloudtrail_trails()[0]
    assert resource.attributes["is_organization_trail"] is None
    assert resource.attributes["organization_trail_scope"] == "unknown"
    assert resource.attributes["data_event_coverage"] == "not_observed"


def test_cloudtrail_denied_selector_access_does_not_claim_no_data_events():
    cloudtrail = Mock()
    cloudtrail.describe_trails.return_value = {"trailList": [{
        "Name": "restricted", "TrailARN": "arn:aws:cloudtrail:eu-west-2:123456789012:trail/restricted",
    }]}
    cloudtrail.get_trail_status.return_value = {"IsLogging": True}
    cloudtrail.get_event_selectors.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive"}}, "GetEventSelectors"
    )
    resource = AWSProvider(cloudtrail_client=cloudtrail).discover_cloudtrail_trails()[0]
    assert resource.attributes["event_selector_discovery"] == "unknown"
    assert resource.attributes["data_event_coverage"] == "unknown"
