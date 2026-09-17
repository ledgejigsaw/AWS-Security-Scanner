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

    with patch(
        "aws_security_scanner.cli.AWSProvider"
    ) as mock_provider:
        mock_provider.return_value.discover_s3_buckets.return_value = [
            resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = []
        mock_provider.return_value.discover_iam_roles.return_value = []

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
        mock_provider.return_value.discover_s3_buckets.return_value = [
            resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = []
        mock_provider.return_value.discover_iam_roles.return_value = []

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

    with patch(
        "aws_security_scanner.cli.AWSProvider"
    ) as mock_provider:
        mock_provider.return_value.discover_s3_buckets.return_value = [
            s3_resource
        ]
        mock_provider.return_value.discover_iam_policies.return_value = [
            iam_policy
        ]
        mock_provider.return_value.discover_iam_roles.return_value = [
            iam_role
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