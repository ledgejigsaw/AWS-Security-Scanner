"""Guardrails shared by opt-in live AWS integration tests."""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any


def live_aws_opted_in(environment: Mapping[str, str] | None = None) -> bool:
    """Return true only for the explicit opt-in value '1'."""
    values = os.environ if environment is None else environment
    return values.get("AWS_SECURITY_SCANNER_LIVE_AWS") == "1"


def validate_expected_account_id(value: str | None) -> str:
    """Require an explicit 12-digit expected AWS account ID."""
    if not isinstance(value, str) or len(value) != 12 or not value.isdigit():
        raise ValueError("expected AWS account ID must contain exactly 12 digits")
    return value


def verify_caller_account(identity: Mapping[str, Any], expected_account_id: str) -> None:
    """Fail closed unless STS identity matches the explicitly expected account."""
    expected = validate_expected_account_id(expected_account_id)
    if identity.get("Account") != expected:
        raise ValueError("caller account does not match the expected test account")
