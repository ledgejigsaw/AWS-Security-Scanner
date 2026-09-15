from typing import Any

import boto3

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
        """Discover S3 buckets and return normalised resources."""

        response = self.s3_client.list_buckets()

        resources = []

        for bucket in response.get("Buckets", []):
            resources.append(
                Resource(
                    resource_type="aws_s3_bucket",
                    resource_id=bucket["Name"],
                    attributes=bucket,
                    source="aws",
                    region=self.region,
                )
            )

        return resources