from unittest.mock import patch

from aws_security_scanner.cli import build_parser, discover_resources


def test_cli_accepts_config_service_filter():
    args = build_parser().parse_args([
        "--source", "aws",
        "--service", "config",
        "--region", "eu-west-2",
    ])
    assert args.service == ["config"]


def test_discovery_invokes_only_config_when_selected():
    with patch("aws_security_scanner.cli.AWSProvider") as provider_cls:
        provider_cls.return_value.discover_aws_config.return_value = ["config-resource"]
        resources = discover_resources("aws", region="eu-west-2", services=["config"])

    assert resources == ["config-resource"]
    provider_cls.return_value.discover_aws_config.assert_called_once_with()
    provider_cls.return_value.discover_s3_buckets.assert_not_called()
