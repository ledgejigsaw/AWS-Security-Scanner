from pathlib import Path

from aws_security_scanner.cli import build_parser, run_scan


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

    assert len(findings) == 7
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

    assert len(findings) == 6
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