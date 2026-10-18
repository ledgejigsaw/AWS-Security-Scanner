"""Opt-in live AWS smoke tests; never mutate AWS resources.

Run with AWS_SECURITY_SCANNER_LIVE_AWS=1 and
AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID=<12-digit dedicated test account>.
"""
from __future__ import annotations

import os

import boto3
import pytest
from botocore.exceptions import BotoCoreError, ClientError


pytestmark = pytest.mark.live_aws


def _live_session() -> boto3.Session:
    if os.getenv("AWS_SECURITY_SCANNER_LIVE_AWS") != "1":
        pytest.skip("set AWS_SECURITY_SCANNER_LIVE_AWS=1 to opt in to live AWS tests")

    expected = os.getenv("AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID", "")
    if len(expected) != 12 or not expected.isdigit():
        pytest.fail(
            "live AWS tests require AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID "
            "to be a 12-digit account ID"
        )
    profile = os.getenv("AWS_SECURITY_SCANNER_AWS_PROFILE")
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def test_live_identity_matches_explicit_test_account_and_s3_is_read_only() -> None:
    """Verify account identity before making a read-only discovery request."""
    session = _live_session()
    expected = os.environ["AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID"]

    try:
        identity = session.client("sts").get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        pytest.fail(f"unable to verify live AWS caller identity ({type(exc).__name__})")

    assert identity.get("Account") == expected, (
        "refusing live test: caller account does not match "
        "AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID"
    )

    # This is deliberately a read-only smoke test. No create/update/delete APIs
    # are called and no account resources are provisioned or cleaned up.
    try:
        response = session.client("s3").list_buckets()
    except (BotoCoreError, ClientError) as exc:
        pytest.fail(f"read-only S3 discovery failed ({type(exc).__name__})")

    assert isinstance(response.get("Buckets"), list)
