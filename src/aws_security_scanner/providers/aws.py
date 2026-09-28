from typing import Any

import boto3
from botocore.exceptions import ClientError
from rich import region

from aws_security_scanner.models.resource import Resource


class AWSProvider:
    """Discover AWS resources using read-only boto3 clients."""

    def __init__(
        self,
        s3_client: Any | None = None,
        iam_client: Any | None = None,
        ec2_client: Any | None = None,
        region: str | None = None,
    ):
        self.region = region

        self.s3_client = s3_client or boto3.client(
            "s3",
            region_name=region,
    )

        self.iam_client = iam_client or boto3.client(
            "iam",
            region_name=region,
    )

        self.ec2_client = ec2_client or boto3.client(
            "ec2",
            region_name=region,
    )

    def discover_s3_buckets(self) -> list[Resource]:
        """Discover S3 buckets and their security configuration."""

        response = self.s3_client.list_buckets()

        resources = []

        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]

            attributes = bucket.copy()

            attributes["encryption"] = (
                self._get_bucket_encryption(bucket_name)
            )

            attributes["versioning"] = (
                self._get_bucket_versioning(bucket_name)
            )

            attributes["block_public_access"] = (
                self._get_block_public_access(bucket_name)
            )

            attributes["logging"] = (
                self._get_bucket_logging(bucket_name)
            )

            attributes["bucket_policy"] = (
                self._get_bucket_policy(bucket_name)
            )

            resources.append(
                Resource(
                    resource_type="aws_s3_bucket",
                    resource_id=bucket_name,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources

    def discover_ec2_instances(self) -> list[Resource]:
        """Discover EC2 instances and normalise security attributes."""

        resources = []

        response = self.ec2_client.describe_instances()

        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                metadata_options = instance.get(
                    "MetadataOptions",
                    {},
                )

                attributes = {
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "public_ip_address": instance.get(
                        "PublicIpAddress"
                    ),
                    "private_ip_address": instance.get(
                        "PrivateIpAddress"
                    ),
                    "subnet_id": instance.get("SubnetId"),
                    "vpc_id": instance.get("VpcId"),
                    "metadata_options": {
                        "http_tokens": metadata_options.get(
                            "HttpTokens"
                        ),
                    },
                    "security_group_ids": [
                        group["GroupId"]
                        for group in instance.get(
                            "SecurityGroups",
                            [],
                        )
                    ],
                }

                resources.append(
                    Resource(
                        resource_type="aws_instance",
                        resource_id=instance_id,
                        attributes=attributes,
                        source="aws",
                        region=self.region,
                    )
                )

        return resources

    def discover_iam_policies(self) -> list[Resource]:
    
        resources = []
        marker = None

        while True:
            if marker:
                response = self.iam_client.list_policies(
                    Scope="Local",
                    Marker=marker,
                )
            else:
                response = self.iam_client.list_policies(
                    Scope="Local",
                )

            for policy in response.get("Policies", []):
                policy_name = policy["PolicyName"]
                policy_arn = policy["Arn"]
                version_id = policy["DefaultVersionId"]

                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id,
                )

                policy_document = version_response[
                    "PolicyVersion"
                ]["Document"]

                resources.append(
                    Resource(
                        resource_type="aws_iam_policy",
                        resource_id=policy_name,
                        attributes={
                            "policy_document": policy_document,
                        },
                        source="aws",
                        region=self.region,
                    )
                )

            if not response.get("IsTruncated"):
                break

            marker = response.get("Marker")

        return resources

    def discover_iam_roles(self) -> list[Resource]:
        """Discover IAM roles and their trust policies."""

        resources = []
        marker = None

        while True:
            if marker:
                response = self.iam_client.list_roles(
                    Marker=marker,
                )
            else:
                response = self.iam_client.list_roles()

            for role in response.get("Roles", []):
                role_name = role["RoleName"]

                assume_role_policy = role.get(
                    "AssumeRolePolicyDocument"
                )

                resources.append(
                    Resource(
                        resource_type="aws_iam_role",
                        resource_id=role_name,
                        attributes={
                            "assume_role_policy_document": (
                                assume_role_policy
                            ),
                        },
                        source="aws",
                        region=self.region,
                    )
                )

            if not response.get("IsTruncated"):
                break

            marker = response.get("Marker")

        return resources

    def _get_bucket_encryption(self, bucket_name: str) -> bool:
        """Return whether server-side encryption is configured."""

        try:
            response = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                return False

            raise

        return bool(response.get("ServerSideEncryptionConfiguration"))

    def _get_bucket_versioning(self, bucket_name: str) -> bool:
        """Return whether versioning is enabled for an S3 bucket."""

        try:
            response = self.s3_client.get_bucket_versioning(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        return response.get("Status") == "Enabled"

    def _get_block_public_access(
    self,
    bucket_name: str,
) -> bool:
        """Return whether S3 Block Public Access is fully enabled."""

        try:
            response = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == "NoSuchPublicAccessBlockConfiguration":
                return False

            raise

        configuration = response.get(
            "PublicAccessBlockConfiguration",
            {},
        )

        return all(
            configuration.get(setting) is True
            for setting in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )

    def _get_bucket_logging(
        self,
        bucket_name: str,
    ) -> bool:
        """Return whether S3 server access logging is enabled."""

        try:
            response = self.s3_client.get_bucket_logging(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        return bool(response.get("LoggingEnabled"))

    def _get_bucket_policy(
        self,
        bucket_name: str,
    ) -> dict | None:
        """Return the S3 bucket policy as a dictionary."""

        try:
            response = self.s3_client.get_bucket_policy(
                Bucket=bucket_name
            )
        except ClientError:
            return None

        policy = response.get("Policy")

        if not isinstance(policy, str):
            return None

        return json.loads(policy)

    def discover_ec2_instances(self) -> list[Resource]:
        """Discover EC2 instances and relevant security attributes."""

        resources = []

        response = self.ec2_client.describe_instances()

        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                attributes = {
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "public_ip_address": instance.get(
                        "PublicIpAddress"
                    ),
                    "private_ip_address": instance.get(
                        "PrivateIpAddress"
                    ),
                    "subnet_id": instance.get("SubnetId"),
                    "vpc_id": instance.get("VpcId"),
                    "metadata_options": instance.get(
                        "MetadataOptions",
                        {},
                    ),
                    "security_group_ids": [
                        group["GroupId"]
                        for group in instance.get(
                            "SecurityGroups",
                            [],
                        )
                    ],
                }

                resources.append(
                    Resource(
                        resource_type="aws_instance",
                        resource_id=instance_id,
                        attributes=attributes,
                        source="aws",
                        region=self.region,
                    )
                )

        return resources

    def discover_security_groups(self) -> list[Resource]:
        """Discover EC2 security groups and normalise network rules."""

        resources = []

        response = self.ec2_client.describe_security_groups()

        for security_group in response.get("SecurityGroups", []):
            group_id = security_group["GroupId"]

            ingress_rules = []

            for permission in security_group.get(
                "IpPermissions",
                [],
            ):
                protocol = permission.get("IpProtocol")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr:
                        ingress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

                for ipv6_range in permission.get(
                    "Ipv6Ranges",
                    [],
                ):
                    cidr = ipv6_range.get("CidrIpv6")

                    if cidr:
                        ingress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

            egress_rules = []

            for permission in security_group.get(
                "IpPermissionsEgress",
                [],
            ):
                protocol = permission.get("IpProtocol")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr:
                        egress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

                for ipv6_range in permission.get(
                    "Ipv6Ranges",
                    [],
                ):
                    cidr = ipv6_range.get("CidrIpv6")

                    if cidr:
                        egress_rules.append(
                            {
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                            }
                        )

            attributes = {
                "group_name": security_group.get("GroupName"),
                "vpc_id": security_group.get("VpcId"),
                "ingress_rules": ingress_rules,
                "egress_rules": egress_rules,
            }

            resources.append(
                Resource(
                    resource_type="aws_security_group",
                    resource_id=group_id,
                    attributes=attributes,
                    source="aws",
                    region=self.region,
                )
            )

        return resources
