import json
from typing import Any

import boto3
from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource


class AWSProvider:
    """Discover AWS resources using read-only boto3 clients."""

    def __init__(
        self,
        s3_client: Any | None = None,
        region: str | None = None,
    ):
        self.region = region

        self.s3_client = s3_client or boto3.client(
            "s3",
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

    def _get_bucket_encryption(self, bucket_name: str) -> bool:
        """Return whether default server-side encryption is configured."""

        try:
            response = self.s3_client.get_bucket_encryption(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        configuration = response.get(
            "ServerSideEncryptionConfiguration",
            {},
        )

        rules = configuration.get("Rules", [])

        return bool(rules)

    def _get_bucket_versioning(self, bucket_name: str) -> bool:
        """Return whether S3 bucket versioning is enabled."""

        response = self.s3_client.get_bucket_versioning(
            Bucket=bucket_name
        )

        return response.get("Status") == "Enabled"

    def _get_block_public_access(self, bucket_name: str) -> bool:
        """Return whether all S3 public access blocks are enabled."""

        try:
            response = self.s3_client.get_public_access_block(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        configuration = response.get(
            "PublicAccessBlockConfiguration",
            {},
        )

        return all(
            configuration.get(setting, False)
            for setting in (
                "BlockPublicAcls",
                "BlockPublicPolicy",
                "IgnorePublicAcls",
                "RestrictPublicBuckets",
            )
        )

    def _get_bucket_logging(self, bucket_name: str) -> bool:
        """Return whether S3 server access logging is enabled."""

        try:
            response = self.s3_client.get_bucket_logging(
                Bucket=bucket_name
            )
        except ClientError:
            return False

        return bool(response.get("LoggingEnabled"))

    def _get_bucket_policy(self, bucket_name: str) -> dict | None:
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