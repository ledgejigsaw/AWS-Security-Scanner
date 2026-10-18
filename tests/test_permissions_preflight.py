from unittest.mock import Mock

from botocore.exceptions import ClientError

from aws_security_scanner.permissions_preflight import run_aws_permissions_preflight


def _session(account="123456789012"):
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {
        "Account": account,
        "Arn": f"arn:aws:iam::{account}:role/audit",
    }
    session.client.return_value.list_buckets.return_value = {"Buckets": []}
    return session


def test_preflight_success_is_limited_to_representative_read_only_probe():
    session = _session()
    result = run_aws_permissions_preflight(session, region="eu-west-2", services=["s3"])
    assert result["status"] == "complete"
    assert result["identity"]["account_id"] == "123456789012"
    assert result["checks"] == [{
        "service": "s3", "operation": "list_buckets", "outcome": "success",
        "iam_action": "s3:ListAllMyBuckets", "error_category": None,
        "scope": "eu-west-2",
    }]
    assert "does not prove every discovery API" in result["limitations"][1]


def test_preflight_access_denied_is_a_gap_and_does_not_leak_error_message():
    session = _session()
    session.client.return_value.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive account details"}},
        "ListBuckets",
    )
    result = run_aws_permissions_preflight(session, region="eu-west-2", services=["s3"])
    assert result["status"] == "incomplete"
    assert result["checks"][0]["outcome"] == "access_denied"
    assert result["checks"][0]["error_category"] == "authorization"
    assert "sensitive account details" not in str(result)


def test_preflight_marks_guardduty_without_detector_as_disabled():
    session = _session()
    session.client.return_value.list_detectors.return_value = {"DetectorIds": []}
    result = run_aws_permissions_preflight(session, region="eu-west-2", services=["guardduty"])
    assert result["status"] == "incomplete"
    assert result["checks"][0]["outcome"] == "disabled"
    assert result["checks"][0]["error_category"] == "no_detector"


def test_preflight_rejects_malformed_sts_identity_without_running_probes():
    session = _session(account="not-an-account")
    result = run_aws_permissions_preflight(session, region="eu-west-2", services=["s3"])
    assert result["status"] == "failed"
    assert result["checks"] == []
    assert result["diagnostics"] == ["invalid_caller_identity"]
