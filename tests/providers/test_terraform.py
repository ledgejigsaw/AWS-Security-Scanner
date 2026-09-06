from pathlib import Path

from aws_security_scanner.providers.terraform import TerraformProvider


def test_terraform_provider_discovers_resources():
    fixture = Path("tests/fixtures/terraform/s3_buckets.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    assert len(resources) == 2


def test_terraform_provider_normalises_resource():
    fixture = Path("tests/fixtures/terraform/s3_buckets.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    insecure_bucket = resources[0]

    assert insecure_bucket.resource_type == "aws_s3_bucket"
    assert insecure_bucket.resource_id == "insecure_bucket"
    assert insecure_bucket.source == "terraform"
    assert insecure_bucket.region == "eu-west-2"

from pathlib import Path

from aws_security_scanner.providers.terraform import TerraformProvider


def test_terraform_provider_discovers_realistic_s3_resources():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    assert len(resources) == 4


def test_terraform_provider_preserves_terraform_resource_types():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    resource_types = {
        resource.resource_type
        for resource in resources
    }

    assert resource_types == {
        "aws_s3_bucket",
        "aws_s3_bucket_versioning",
    }

def test_terraform_provider_resolves_resource_relationships():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    versioning = next(
        resource
        for resource in resources
        if resource.resource_type == "aws_s3_bucket_versioning"
        and resource.resource_id == "company_data"
    )

    assert versioning.relationships == {
        "bucket": "aws_s3_bucket.company_data"
    }

def test_terraform_provider_leaves_unrelated_resources_without_relationships():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    bucket = next(
        resource
        for resource in resources
        if resource.resource_type == "aws_s3_bucket"
        and resource.resource_id == "company_data"
    )

    assert bucket.relationships is None

def test_terraform_provider_resolves_nested_relationships():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)

    resources = provider.discover()

    versioning = next(
        resource
        for resource in resources
        if resource.resource_type == "aws_s3_bucket_versioning"
        and resource.resource_id == "company_data"
    )

    assert versioning.relationships == {
        "bucket": "aws_s3_bucket.company_data"
    }