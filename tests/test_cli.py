import json

from pathlib import Path
from unittest.mock import patch

from aws_security_scanner.cli import build_parser, run_scan
from aws_security_scanner.models.resource import Resource

def test_cli_accepts_policy_argument():
    parser = build_parser()

    args = parser.parse_args(
        [
            "--source",
            "terraform",
            "--file",
            "tests/fixtures/terraform/realistic_s3.json",
            "--policy",
            "policies/default.yaml",
        ]
    )

    assert args.policy == Path("policies/default.yaml")



def test_cli_accepts_sarif_report_format():
    parser = build_parser()
    args = parser.parse_args([
        "--source", "terraform",
        "--file", "tests/fixtures/terraform/realistic_s3.json",
        "--format", "sarif",
    ])
    assert args.format == "sarif"
    assert args.output is None


def test_cli_accepts_html_report_format():
    parser = build_parser()

    args = parser.parse_args(
        [
            "--source",
            "terraform",
            "--file",
            "tests/fixtures/terraform/realistic_s3.json",
            "--format",
            "html",
        ]
    )

    assert args.format == "html"
    assert args.output is None

def test_run_scan_without_policy_preserves_default_behaviour():
    findings = run_scan(
        "terraform",
        Path("tests/fixtures/terraform/realistic_s3.json"),
    )

    check_ids = {finding.check_id for finding in findings}

    assert len(findings) == 9
    assert "S3-001" in check_ids


def test_run_scan_can_disable_rule(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules:
  S3-001:
    enabled: false
"""
    )

    findings = run_scan(
        "terraform",
        Path("tests/fixtures/terraform/realistic_s3.json"),
        policy_file,
    )

    check_ids = {finding.check_id for finding in findings}

    assert len(findings) == 8
    assert "S3-001" not in check_ids

def test_run_scan_can_override_rule_severity(tmp_path):
    terraform_file = tmp_path / "terraform.json"

    terraform_file.write_text(
        """
{
    "resource": {
        "aws_s3_bucket": {
            "company_data": {
                "bucket": "company-sensitive-data",
                "region": "eu-west-2"
            }
        }
    }
}
"""
    )

    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules:
  S3-002:
    enabled: true
    severity: CRITICAL
"""
    )

    findings = run_scan(
        "terraform",
        terraform_file,
        policy_file,
    )

    encryption_findings = [
        finding
        for finding in findings
        if finding.check_id == "S3-002"
    ]

    assert len(encryption_findings) == 1
    assert encryption_findings[0].severity.value == "CRITICAL"

def test_run_scan_uses_aws_provider():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "encryption": False,
            "versioning": False,
            "block_public_access": False,
            "logging": False,
        },
        source="aws",
        region="eu-west-2",
    )
    rds_resource = Resource(
        resource_type="aws_db_instance",
        resource_id="customer-db",
        attributes={
            "storage_encrypted": False,
            "publicly_accessible": False,
            "backup_retention_period": 7,
            "deletion_protection": True,
        },
        source="aws",
        region="eu-west-2",
    )

    secret_resource = Resource(
        resource_type="aws_secretsmanager_secret",
        resource_id="customer-api-token",
        attributes={
            "rotation_enabled": False,
            "resource_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }]
            },
        },
        source="aws",
        region="eu-west-2",
    )

    lambda_resource = Resource(
        resource_type="aws_lambda_function",
        resource_id="public-handler",
        attributes={
            "function_url_auth_type": "NONE",
            "resource_policy": None,
        },
        source="aws",
        region="eu-west-2",
    )

    with patch(
        "aws_security_scanner.cli.AWSProvider"
    ) as mock_provider:
        mock_provider.return_value.discover_lambda_functions.return_value = []
        mock_provider.return_value.discover_secrets_manager_secrets.return_value = [secret_resource]
        mock_provider.return_value.discover_rds_instances.return_value = [rds_resource]
        mock_provider.return_value.discover_lambda_functions.return_value = [lambda_resource]
        mock_provider.return_value.discover_iam_users.return_value = []
        mock_provider.return_value.discover_iam_account.return_value = []
        mock_provider.return_value.discover_s3_buckets.return_value = [
            resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = []
        mock_provider.return_value.discover_iam_roles.return_value = []
        cloudtrail_resource = Resource(
            resource_type="aws_cloudtrail_trail",
            resource_id="trail-example",
            attributes={
                "is_logging": False,
                "is_multi_region_trail": True,
                "log_file_validation_enabled": False,
            },
            source="aws",
            region="eu-west-2",
        )
        kms_resource = Resource(
            resource_type="aws_kms_key",
            resource_id="key-example",
            attributes={
                "rotation_applicable": True,
                "rotation_enabled": True,
                "key_state": "Enabled",
                "key_policy": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "kms:*",
                        "Resource": "*",
                    }]
                },
            },
            source="aws",
            region="eu-west-2",
        )
        mock_provider.return_value.discover_cloudtrail_trails.return_value = [cloudtrail_resource]
        mock_provider.return_value.discover_kms_keys.return_value = [kms_resource]

        findings = run_scan(
            "aws",
            region="eu-west-2",
        )

    mock_provider.assert_called_once_with(
        region="eu-west-2"
    )

    check_ids = {
        finding.check_id
        for finding in findings
    }

    assert "S3-002" in check_ids
    assert "S3-003" in check_ids
    assert "S3-004" in check_ids
    assert "S3-005" in check_ids

    assert "RDS-001" in check_ids
    assert "LAMBDA-001" in check_ids

def test_aws_scan_can_write_json_report(tmp_path):
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "encryption": False,
            "versioning": False,
            "block_public_access": False,
            "logging": False,
        },
        source="aws",
        region="eu-west-2",
    )

    output_path = tmp_path / "aws-scan.json"

    with patch(
        "aws_security_scanner.cli.AWSProvider"
    ) as mock_provider:
        mock_provider.return_value.discover_lambda_functions.return_value = []
        mock_provider.return_value.discover_rds_instances.return_value = []
        mock_provider.return_value.discover_iam_users.return_value = []
        mock_provider.return_value.discover_iam_account.return_value = []
        mock_provider.return_value.discover_s3_buckets.return_value = [
            resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = []
        mock_provider.return_value.discover_iam_roles.return_value = []
        mock_provider.return_value.discover_cloudtrail_trails.return_value = []
        mock_provider.return_value.discover_kms_keys.return_value = []

        findings = run_scan(
            "aws",
            region="eu-west-2",
        )

    from aws_security_scanner.reporting.json_reporter import (
        write_json_report,
    )

    write_json_report(findings, output_path)

    assert output_path.exists()

    with output_path.open(encoding="utf-8") as file:
        report = json.load(file)


    assert report["summary"]["total_findings"] == 5

    check_ids = {
        finding["check_id"]
        for finding in report["findings"]
    }

    assert "S3-002" in check_ids
    assert "S3-003" in check_ids
    assert "S3-004" in check_ids
    assert "S3-005" in check_ids
    assert "S3-007" in check_ids

def test_run_scan_uses_s3_and_iam_resources():
    s3_resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-data",
        attributes={
            "encryption": False,
            "versioning": False,
            "block_public_access": True,
            "logging": True,
        },
        source="aws",
        region="eu-west-2",
    )

    iam_policy = Resource(
        resource_type="aws_iam_policy",
        resource_id="admin-policy",
        attributes={
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ],
            }
        },
        source="aws",
        region="eu-west-2",
    )

    iam_role = Resource(
        resource_type="aws_iam_role",
        resource_id="insecure-role",
        attributes={
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        },
        source="aws",
        region="eu-west-2",
    )

    cloudtrail_resource = Resource(
        resource_type="aws_cloudtrail_trail",
        resource_id="trail-example",
        attributes={
            "is_logging": False,
            "is_multi_region_trail": True,
            "log_file_validation_enabled": False,
        },
        source="aws",
        region="eu-west-2",
    )

    kms_resource = Resource(
        resource_type="aws_kms_key",
        resource_id="key-example",
        attributes={
            "rotation_applicable": True,
            "rotation_enabled": True,
            "key_state": "Enabled",
            "key_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                }]
            },
        },
        source="aws",
        region="eu-west-2",
    )

    secret_resource = Resource(
        resource_type="aws_secretsmanager_secret",
        resource_id="customer-api-token",
        attributes={
            "rotation_enabled": False,
            "resource_policy": {
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }]
            },
        },
        source="aws",
        region="eu-west-2",
    )

    with patch(
        "aws_security_scanner.cli.AWSProvider"
    ) as mock_provider:
        mock_provider.return_value.discover_lambda_functions.return_value = []
        mock_provider.return_value.discover_secrets_manager_secrets.return_value = [secret_resource]
        mock_provider.return_value.discover_rds_instances.return_value = []
        mock_provider.return_value.discover_iam_users.return_value = []
        mock_provider.return_value.discover_iam_account.return_value = []
        mock_provider.return_value.discover_s3_buckets.return_value = [
            s3_resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = [
            iam_policy
        ]
        mock_provider.return_value.discover_iam_roles.return_value = [
            iam_role
        ]
        mock_provider.return_value.discover_cloudtrail_trails.return_value = [
            cloudtrail_resource
        ]
        mock_provider.return_value.discover_kms_keys.return_value = [
            kms_resource
        ]

        findings = run_scan(
            "aws",
            region="eu-west-2",
        )

    check_ids = {
        finding.check_id
        for finding in findings
    }

    assert "S3-002" in check_ids
    assert "IAM-001" in check_ids
    assert "IAM-004" in check_ids
    assert "CT-001" in check_ids
    assert "CT-003" in check_ids
    assert "KMS-003" in check_ids
    assert "SM-001" in check_ids
    assert "SM-002" in check_ids


def test_aws_scan_includes_iam_user_and_account_findings():
    user = Resource(
        resource_type="aws_iam_user",
        resource_id="user-without-mfa",
        attributes={
            "mfa_enabled": False,
            "access_keys": [],
            "password_enabled": False,
            "inline_policies": [],
        },
        source="aws",
    )
    account = Resource(
        resource_type="aws_iam_account",
        resource_id="root",
        attributes={
            "root_mfa_enabled": False,
            "root_access_key_1_active": False,
            "root_access_key_2_active": False,
        },
        source="aws",
    )

    with patch("aws_security_scanner.cli.AWSProvider") as mock_provider:
        provider = mock_provider.return_value
        provider.discover_s3_buckets.return_value = []
        provider.discover_iam_policies.return_value = []
        provider.discover_iam_roles.return_value = []
        provider.discover_iam_users.return_value = [user]
        provider.discover_iam_account.return_value = [account]
        provider.discover_ec2_instances.return_value = []
        provider.discover_security_groups.return_value = []
        provider.discover_vpcs.return_value = []
        provider.discover_subnets.return_value = []
        provider.discover_route_tables.return_value = []
        provider.discover_network_acls.return_value = []
        provider.discover_flow_logs.return_value = []
        provider.discover_cloudtrail_trails.return_value = []
        provider.discover_kms_keys.return_value = []

        findings = run_scan("aws", region="eu-west-2")

    check_ids = {finding.check_id for finding in findings}
    assert "IAM-005" in check_ids
    assert "IAM-013" in check_ids



def test_cli_accepts_minimum_severity_and_baseline_options():
    parser = build_parser()
    args = parser.parse_args([
        "--source", "terraform",
        "--file", "tests/fixtures/terraform/realistic_s3.json",
        "--min-severity", "HIGH",
        "--baseline", "reports/baseline.json",
    ])

    assert args.min_severity == "HIGH"
    assert args.baseline == Path("reports/baseline.json")
    assert args.write_baseline is None


def test_cli_accepts_write_baseline_option():
    parser = build_parser()
    args = parser.parse_args([
        "--source", "terraform",
        "--file", "tests/fixtures/terraform/realistic_s3.json",
        "--write-baseline", "reports/baseline.json",
    ])

    assert args.write_baseline == Path("reports/baseline.json")
    assert args.baseline is None
