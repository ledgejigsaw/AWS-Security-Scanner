import pytest

from aws_security_scanner.live_aws import (
    live_aws_opted_in,
    validate_expected_account_id,
    verify_caller_account,
)


def test_live_aws_requires_explicit_opt_in():
    assert live_aws_opted_in({}) is False
    assert live_aws_opted_in({"AWS_SECURITY_SCANNER_LIVE_AWS": "true"}) is False
    assert live_aws_opted_in({"AWS_SECURITY_SCANNER_LIVE_AWS": "1"}) is True


@pytest.mark.parametrize("value", [None, "", "123", "12345678901", "12345678901x"])
def test_expected_account_id_must_be_exactly_twelve_digits(value):
    with pytest.raises(ValueError):
        validate_expected_account_id(value)


def test_identity_mismatch_fails_closed():
    with pytest.raises(ValueError, match="does not match"):
        verify_caller_account({"Account": "111111111111"}, "222222222222")


def test_matching_identity_is_accepted():
    verify_caller_account({"Account": "123456789012"}, "123456789012")
