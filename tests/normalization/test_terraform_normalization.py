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
