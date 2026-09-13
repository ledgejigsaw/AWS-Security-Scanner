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

    assert len(findings) == 5
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

    assert len(findings) == 4
    assert "S3-001" not in check_ids