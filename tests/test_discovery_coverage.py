from unittest.mock import patch

from botocore.exceptions import ClientError

from aws_security_scanner.cli import discover_resources
from aws_security_scanner.models.resource import Resource


def _access_denied():
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive request details"}},
        "ListBuckets",
    )


def test_discovery_coverage_distinguishes_partial_service_failure():
    bucket = Resource(
        resource_type="aws_s3_bucket",
        resource_id="example-bucket",
        attributes={},
        source="aws",
        region="eu-west-2",
    )
    coverage = []

    with patch("aws_security_scanner.cli.AWSProvider") as provider_factory:
        provider = provider_factory.return_value
        provider.discover_s3_buckets.return_value = [bucket]
        provider.discover_s3_account_public_access_block.side_effect = _access_denied()

        resources = discover_resources(
            "aws",
            region="eu-west-2",
            services=["s3"],
            discovery_coverage=coverage,
        )

    assert resources == [bucket]
    assert coverage == [{
        "service": "s3",
        "status": "partial",
        "resources_discovered": 1,
        "successful_operations": 1,
        "failed_operations": [{
            "operation": "discover_s3_account_public_access_block",
            "error_code": "AccessDenied",
        }],
    }]
    assert "sensitive request details" not in str(coverage)


def test_discovery_coverage_marks_denied_service_failed():
    coverage = []

    with patch("aws_security_scanner.cli.AWSProvider") as provider_factory:
        provider = provider_factory.return_value
        provider.discover_s3_buckets.side_effect = _access_denied()
        provider.discover_s3_account_public_access_block.side_effect = _access_denied()

        resources = discover_resources(
            "aws",
            region="eu-west-2",
            services=["s3"],
            discovery_coverage=coverage,
        )

    assert resources == []
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["resources_discovered"] == 0
    assert len(coverage[0]["failed_operations"]) == 2


def test_discovery_coverage_marks_successful_empty_service():
    coverage = []

    with patch("aws_security_scanner.cli.AWSProvider") as provider_factory:
        provider = provider_factory.return_value
        provider.discover_s3_buckets.return_value = []
        provider.discover_s3_account_public_access_block.return_value = []

        resources = discover_resources(
            "aws",
            region="eu-west-2",
            services=["s3"],
            discovery_coverage=coverage,
        )

    assert resources == []
    assert coverage[0]["status"] == "empty"
    assert coverage[0]["successful_operations"] == 2
