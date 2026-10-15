from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from aws_security_scanner.cli import build_parser, discover_resources, run_scan


def test_cli_accepts_profile_and_repeated_service_filters():
    args = build_parser().parse_args([
        "--source", "aws",
        "--profile", "security-audit",
        "--region", "eu-west-2",
        "--service", "s3",
        "--service", "iam",
        "--service", "macie",
    ])
    assert args.profile == "security-audit"
    assert args.service == ["s3", "iam", "macie"]


def test_discovery_only_invokes_selected_service_methods():
    with patch("aws_security_scanner.cli.AWSProvider") as provider_cls:
        provider_cls.return_value.discover_s3_buckets.return_value = ["bucket"]
        resources = discover_resources("aws", region="eu-west-2", services=["s3"])

    assert resources == ["bucket"]
    provider_cls.return_value.discover_s3_buckets.assert_called_once_with()
    provider_cls.return_value.discover_iam_policies.assert_not_called()
    provider_cls.return_value.discover_ec2_instances.assert_not_called()
    provider_cls.return_value.discover_cloudtrail_trails.assert_not_called()


def test_run_scan_uses_selected_boto3_profile_and_limits_services():
    session = Mock()
    bucket = Mock()
    with (
        patch("aws_security_scanner.cli.boto3.Session", return_value=session) as session_factory,
        patch("aws_security_scanner.cli.AWSProvider") as provider_cls,
        patch("aws_security_scanner.cli.RuleEngine") as engine_cls,
    ):
        provider_cls.return_value.discover_s3_buckets.return_value = [bucket]
        engine_cls.return_value.scan.return_value = []
        findings = run_scan(
            "aws",
            region="eu-west-2",
            profile="security-audit",
            services=["s3"],
        )

    assert findings == []
    session_factory.assert_called_once_with(profile_name="security-audit", region_name="eu-west-2")
    provider_cls.assert_called_once_with(region="eu-west-2", session=session)
    provider_cls.return_value.discover_s3_buckets.assert_called_once_with()
    provider_cls.return_value.discover_iam_policies.assert_not_called()


@pytest.mark.parametrize("source", ["fixture", "terraform"])
def test_run_scan_rejects_profile_for_non_aws_source(source):
    with pytest.raises(ValueError, match="only be used with --source aws"):
        run_scan(source, Path("unused.json"), profile="security-audit")


def test_run_scan_rejects_unknown_service_name():
    with pytest.raises(ValueError, match="Unsupported AWS service selection"):
        run_scan("aws", services=["not-a-service"])



def test_discovery_invokes_macie_only_when_selected():
    with patch("aws_security_scanner.cli.AWSProvider") as provider_cls:
        provider_cls.return_value.discover_macie_session.return_value = ["macie"]
        resources = discover_resources("aws", region="eu-west-2", services=["macie"])

    assert resources == ["macie"]
    provider_cls.return_value.discover_macie_session.assert_called_once_with()
    provider_cls.return_value.discover_s3_buckets.assert_not_called()
