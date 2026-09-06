from pathlib import Path

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.normalization.terraform import aggregate_s3_resources


def test_terraform_s3_resources_are_aggregated():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    aggregated = aggregate_s3_resources(resources)

    company_data = next(
        resource
        for resource in aggregated
        if resource.resource_id == "company_data"
    )

    assert company_data.resource_type == "aws_s3_bucket"

    assert company_data.attributes["bucket"] == "company-sensitive-data"

    assert company_data.attributes["versioning_configuration"]["status"] == "Disabled"

def test_terraform_s3_encryption_is_aggregated():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    aggregated = aggregate_s3_resources(resources)

    company_data = next(
        resource
        for resource in aggregated
        if resource.resource_id == "company_data"
    )

    encryption = company_data.attributes[
        "server_side_encryption_configuration"
    ]

    assert (
        encryption["rule"][
            "apply_server_side_encryption_by_default"
        ]["sse_algorithm"]
        == "AES256"
    )

def test_terraform_s3_public_access_block_is_aggregated():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    aggregated = aggregate_s3_resources(resources)

    company_data = next(
        resource
        for resource in aggregated
        if resource.resource_id == "company_data"
    )

    public_access = company_data.attributes["public_access_block"]

    assert public_access["block_public_acls"] is False
    assert public_access["block_public_policy"] is False
    assert public_access["ignore_public_acls"] is False
    assert public_access["restrict_public_buckets"] is False

def test_terraform_s3_logging_is_aggregated():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    aggregated = aggregate_s3_resources(resources)

    company_data = next(
        resource
        for resource in aggregated
        if resource.resource_id == "company_data"
    )

    logging = company_data.attributes["logging"]

    assert logging["target_bucket"] == ""

def test_terraform_s3_aggregation_returns_only_base_buckets():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    aggregated = aggregate_s3_resources(resources)

    assert len(aggregated) == 2

    assert all(
        resource.resource_type == "aws_s3_bucket"
        for resource in aggregated
    )