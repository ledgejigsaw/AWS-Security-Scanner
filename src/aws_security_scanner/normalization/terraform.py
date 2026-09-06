from aws_security_scanner.models.resource import Resource


def aggregate_s3_resources(
    resources: list[Resource],
) -> list[Resource]:
    """Aggregate related Terraform S3 resources into their base bucket."""

    buckets = {
        resource.resource_id: resource
        for resource in resources
        if resource.resource_type == "aws_s3_bucket"
    }

    aggregated = []

    for resource in resources:
        if resource.resource_type == "aws_s3_bucket":
            aggregated.append(resource)
            continue

        if resource.resource_type in {
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_logging",
            "aws_s3_bucket_policy",
        }:
            bucket_reference = (
                resource.relationships.get("bucket")
                if resource.relationships
                else None
            )

            if not bucket_reference:
                continue

            bucket_name = bucket_reference.split(".", 1)[1]

            bucket = buckets.get(bucket_name)

            if bucket is None:
                continue

            if resource.resource_type == "aws_s3_bucket_versioning":
                versioning_configuration = resource.attributes.get(
                    "versioning_configuration"
                )

                bucket.attributes["versioning_configuration"] = (
                    versioning_configuration
                )

                bucket.attributes["versioning"] = (
                    versioning_configuration is not None
                    and versioning_configuration.get("status") == "Enabled"
                )

            elif (
                resource.resource_type
                == "aws_s3_bucket_server_side_encryption_configuration"
            ):
                encryption_configuration = resource.attributes.get("rule")

                bucket.attributes["server_side_encryption_configuration"] = {
                    "rule": encryption_configuration
                }

                bucket.attributes["encryption"] = (
                    encryption_configuration is not None
                )

            elif resource.resource_type == "aws_s3_bucket_public_access_block":
                public_access_block = {
                    "block_public_acls": resource.attributes.get(
                        "block_public_acls"
                    ),
                    "block_public_policy": resource.attributes.get(
                        "block_public_policy"
                    ),
                    "ignore_public_acls": resource.attributes.get(
                        "ignore_public_acls"
                    ),
                    "restrict_public_buckets": resource.attributes.get(
                        "restrict_public_buckets"
                    ),
                }

                bucket.attributes["public_access_block"] = (
                    public_access_block
                )

                bucket.attributes["block_public_access"] = all(
                    public_access_block.values()
                )

                bucket.attributes["public"] = not all(
                    public_access_block.values()
                )

            elif resource.resource_type == "aws_s3_bucket_logging":
                target_bucket = resource.attributes.get("target_bucket")

                bucket.attributes["logging_configuration"] = {
                    "target_bucket": target_bucket
                }

                bucket.attributes["logging"] = bool(target_bucket)

            elif resource.resource_type == "aws_s3_bucket_policy":
                policy = resource.attributes.get("policy")

                if policy is not None:
                    bucket.attributes["bucket_policy"] = policy

    return aggregated