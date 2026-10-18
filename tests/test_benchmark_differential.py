import json
from pathlib import Path
from unittest.mock import Mock, patch

from aws_security_scanner.benchmark_differential import (
    normalize_checkov_report,
    normalize_trivy_report,
    run_optional_iac_tool,
    sha256_file,
    validate_upstream_metadata,
)


def test_upstream_metadata_requires_pinned_commit_license_and_digest():
    valid = {
        "repository": "https://github.com/example/project",
        "commit": "a" * 40,
        "license": "Apache-2.0",
        "path": "examples/main.tf",
        "sha256": "b" * 64,
    }
    assert validate_upstream_metadata(valid) == []
    assert "commit_must_be_full_40_character_sha" in validate_upstream_metadata({})


def test_sha256_file_is_deterministic(tmp_path: Path):
    fixture = tmp_path / "sample.tf"
    fixture.write_text("resource \"aws_s3_bucket\" \"sample\" {}\n")
    assert sha256_file(fixture) == sha256_file(fixture)


def test_checkov_adapter_normalizes_resource_and_severity():
    report = {"results": {"failed_checks": [{
        "check_id": "CKV_AWS_20",
        "severity": "HIGH",
        "resource": "aws_s3_bucket.sample",
        "file_path": "main.tf",
        "check_name": "Bucket public",
    }]}}
    assert normalize_checkov_report(report) == [{
        "tool": "checkov", "check_id": "CKV_AWS_20", "severity": "HIGH",
        "resource_address": "aws_s3_bucket.sample", "source_file": "main.tf",
        "title": "Bucket public",
    }]


def test_trivy_adapter_normalizes_misconfigurations():
    report = {"Results": [{
        "Target": "main.tf",
        "Misconfigurations": [{
            "ID": "AVD-AWS-0086", "Severity": "HIGH", "Title": "Bucket encryption",
            "CauseMetadata": {"Resource": "aws_s3_bucket.sample"},
        }],
    }]}
    findings = normalize_trivy_report(report)
    assert findings[0]["check_id"] == "AVD-AWS-0086"
    assert findings[0]["resource_address"] == "aws_s3_bucket.sample"


def test_missing_external_tool_is_reported_as_unavailable():
    with patch("aws_security_scanner.benchmark_differential.shutil.which", return_value=None):
        result = run_optional_iac_tool("trivy", "main.tf")
    assert result["status"] == "unavailable"
    assert result["diagnostics"] == ["tool_not_installed"]


def test_external_tool_invalid_json_fails_without_raw_output():
    completed = Mock(returncode=0, stdout="not json", stderr="sensitive")
    with patch("aws_security_scanner.benchmark_differential.shutil.which", return_value="/usr/bin/trivy"), patch(
        "aws_security_scanner.benchmark_differential.subprocess.run", return_value=completed
    ):
        result = run_optional_iac_tool("trivy", "main.tf")
    assert result["status"] == "failed"
    assert result["diagnostics"] == ["invalid_json_output"]
    assert "sensitive" not in str(result)
