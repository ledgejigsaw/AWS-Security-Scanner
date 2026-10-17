"""Opt-in, read-only integration test for a dedicated AWS test account.

These tests are skipped unless AWS_SECURITY_SCANNER_LIVE_TESTS=1 is explicitly set.
They never create, modify, or delete cloud resources.
"""
import os

import boto3
import pytest

from aws_security_scanner.cli import run_scan


pytestmark = pytest.mark.live_aws


def _required_setting(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"{name} is required when AWS_SECURITY_SCANNER_LIVE_TESTS=1")
    return value


def test_read_only_s3_scan_matches_account_guard_and_expected_findings():
    if os.environ.get("AWS_SECURITY_SCANNER_LIVE_TESTS") != "1":
        pytest.skip("Set AWS_SECURITY_SCANNER_LIVE_TESTS=1 to opt into live AWS tests")

    expected_account = _required_setting("AWS_SECURITY_SCANNER_LIVE_EXPECTED_ACCOUNT_ID")
    expected_bucket = _required_setting("AWS_SECURITY_SCANNER_LIVE_EXPECTED_BUCKET")
    expected_checks_raw = _required_setting("AWS_SECURITY_SCANNER_LIVE_EXPECTED_CHECK_IDS")
    region = os.environ.get("AWS_SECURITY_SCANNER_LIVE_REGION", "eu-west-2")
    profile = os.environ.get("AWS_PROFILE")

    if len(expected_account) != 12 or not expected_account.isdigit():
        pytest.fail("AWS_SECURITY_SCANNER_LIVE_EXPECTED_ACCOUNT_ID must be a 12-digit account ID")

    session = boto3.Session(profile_name=profile or None, region_name=region)
    identity = session.client("sts", region_name=region).get_caller_identity()
    actual_account = identity.get("Account")
    assert actual_account == expected_account, (
        "Refusing to scan: the active AWS identity does not match the explicitly "
        "configured disposable test account."
    )

    findings, resources, coverage = run_scan(
        "aws",
        region=region,
        aws_session=session,
        expected_account_id=expected_account,
        services=["s3"],
        return_resources=True,
        return_coverage=True,
    )

    bucket = next(
        (
            resource for resource in resources
            if resource.resource_type == "aws_s3_bucket"
            and resource.resource_id == expected_bucket
        ),
        None,
    )
    assert bucket is not None, (
        f"Expected pre-created S3 test bucket {expected_bucket!r} was not discovered"
    )

    s3_coverage = next((item for item in coverage if item.get("service") == "s3"), None)
    assert s3_coverage is not None, "The scan did not emit S3 discovery coverage"
    assert s3_coverage.get("status") in {"success", "partial"}, s3_coverage

    expected_checks = (
        set()
        if expected_checks_raw.upper() == "NONE"
        else {item.strip() for item in expected_checks_raw.split(",") if item.strip()}
    )
    actual_checks = {
        finding.check_id for finding in findings
        if finding.resource == expected_bucket
    }
    assert actual_checks == expected_checks, {
        "expected_check_ids": sorted(expected_checks),
        "actual_check_ids": sorted(actual_checks),
        "account_id": actual_account,
        "region": region,
        "bucket": expected_bucket,
    }
