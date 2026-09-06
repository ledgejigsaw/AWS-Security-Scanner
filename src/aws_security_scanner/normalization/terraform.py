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
                bucket.attributes["versioning_configuration"] = (
                    resource.attributes.get("versioning_configuration")
                )

            elif (
                resource.resource_type
                == "aws_s3_bucket_server_side_encryption_configuration"
            ):
                bucket.attributes["server_side_encryption_configuration"] = {
                    "rule": resource.attributes.get("rule")
                }

    return aggregated