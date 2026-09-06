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