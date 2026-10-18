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
    assert coverage[0]["service"] == "s3"
    assert coverage[0]["status"] == "partial"
    assert coverage[0]["resources_discovered"] == 1
    assert coverage[0]["successful_operations"] == 1
    assert coverage[0]["failed_operations"][0]["error_code"] == "AccessDenied"
    assert coverage[0]["failed_operations"][0]["error_category"] == "authorization"
    operations = {item["operation"]: item for item in coverage[0]["operations"]}
    assert operations["discover_s3_buckets"]["outcome"] == "success"
    assert operations["discover_s3_account_public_access_block"]["outcome"] == "access_denied"
    assert coverage[0]["operation_summary"]["status"] == "incomplete"
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


from aws_security_scanner.discovery_coverage import (
    DiscoveryOperation,
    DiscoveryOutcome,
    summarise_discovery_operations,
)


def test_operation_coverage_keeps_successful_empty_distinct_from_failure():
    success = DiscoveryOperation.for_operation(
        "s3", "ListBuckets", "account", DiscoveryOutcome.SUCCESS,
        resources_discovered=0, pages=1, pagination_complete=True,
    )
    denied = DiscoveryOperation.for_operation(
        "iam", "ListPolicies", "account", DiscoveryOutcome.ACCESS_DENIED,
        error_category="authorization",
    )
    report = summarise_discovery_operations([success, denied])
    assert report["status"] == "incomplete"
    assert report["outcome_counts"]["success"] == 1
    assert report["outcome_counts"]["access_denied"] == 1
    assert report["resources_discovered"] == 0
    assert success.iam_action == "s3:ListAllMyBuckets"


def test_operation_coverage_does_not_guess_unknown_iam_actions():
    operation = DiscoveryOperation.for_operation(
        "unknownservice", "UnknownOperation", "eu-west-2", DiscoveryOutcome.SUCCESS,
        pagination_complete=True,
    )
    assert operation.iam_action is None


def test_operation_coverage_reports_throttling_and_incomplete_pagination():
    operations = [
        DiscoveryOperation.for_operation(
            "ec2", "DescribeInstances", "eu-west-2", DiscoveryOutcome.THROTTLED,
            error_category="throttling",
        ),
        DiscoveryOperation.for_operation(
            "ec2", "DescribeInstances", "eu-west-2", DiscoveryOutcome.SUCCESS,
            resources_discovered=3, pages=1, pagination_complete=False,
        ),
    ]
    report = summarise_discovery_operations(operations)
    assert report["status"] == "incomplete"
    assert report["outcome_counts"]["throttled"] == 1
    assert report["resources_discovered"] == 3


def test_operation_coverage_serialization_is_deterministic():
    a = DiscoveryOperation.for_operation("s3", "ListBuckets", "account", DiscoveryOutcome.SUCCESS)
    b = DiscoveryOperation.for_operation("iam", "ListPolicies", "account", DiscoveryOutcome.SUCCESS)
    assert summarise_discovery_operations([a, b]) == summarise_discovery_operations([b, a])


def test_discovery_operation_summary_keeps_empty_success_complete():
    coverage = []
    with patch("aws_security_scanner.cli.AWSProvider") as provider_factory:
        provider = provider_factory.return_value
        provider.discover_s3_buckets.return_value = []
        provider.discover_s3_account_public_access_block.return_value = []
        discover_resources("aws", region="eu-west-2", services=["s3"], discovery_coverage=coverage)
    assert coverage[0]["status"] == "empty"
    assert coverage[0]["operation_summary"]["status"] == "complete"
    assert all(item["outcome"] == "success" for item in coverage[0]["operations"])


def test_discovery_error_classification_does_not_leak_error_messages():
    from aws_security_scanner.discovery_coverage import classify_discovery_error
    outcome, category = classify_discovery_error(_access_denied())
    assert outcome == DiscoveryOutcome.ACCESS_DENIED
    assert category == "authorization"
