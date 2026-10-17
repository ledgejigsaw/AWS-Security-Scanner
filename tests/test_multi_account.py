import json
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from aws_security_scanner.cli import build_parser
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.multi_account import load_account_targets, run_multi_account_scan
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.reporting.html_reporter import build_html_report
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report


ACCOUNT_A = "111111111111"
ACCOUNT_B = "222222222222"
ACCOUNT_C = "333333333333"


def role_target(account_id):
    return {
        "account_id": account_id,
        "role_arn": f"arn:aws:iam::{account_id}:role/SecurityAudit",
    }


def write_accounts_file(path, accounts):
    path.write_text(json.dumps({"accounts": accounts}), encoding="utf-8")
    return path


def sample_finding(account_id=ACCOUNT_A):
    return Finding(
        check_id="S3-001",
        severity=Severity.CRITICAL,
        service="S3",
        resource="example-bucket",
        title="Public bucket",
        description="Bucket is public",
        remediation="Block public access",
        region="eu-west-2",
        account_id=account_id,
    )


def credentials():
    return {
        "Credentials": {
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "example-secret",
            "SessionToken": "example-session-token",
        }
    }


def test_load_account_targets_accepts_explicit_roles_and_external_id(tmp_path):
    path = write_accounts_file(
        tmp_path / "accounts.json",
        [{**role_target(ACCOUNT_A), "external_id": "external-id-value"}],
    )
    targets = load_account_targets(path)
    assert targets == [
        {
            **role_target(ACCOUNT_A),
            "external_id": "external-id-value",
        }
    ]


@pytest.mark.parametrize(
    ("accounts", "message"),
    [
        ([{"account_id": "123", "role_arn": "arn:aws:iam::123:role/Audit"}], "12-digit"),
        ([{"account_id": ACCOUNT_A, "role_arn": f"arn:aws:iam::{ACCOUNT_B}:role/Audit"}], "must match"),
        ([role_target(ACCOUNT_A), role_target(ACCOUNT_A)], "Duplicate"),
        ([{"account_id": ACCOUNT_A, "role_arn": "not-an-arn"}], "IAM role ARN"),
    ],
)
def test_load_account_targets_rejects_invalid_targets(tmp_path, accounts, message):
    path = write_accounts_file(tmp_path / "accounts.json", accounts)
    with pytest.raises(ValueError, match=message):
        load_account_targets(path)


def test_multi_account_scan_keeps_success_and_reports_denied_and_wrong_identity(tmp_path):
    path = write_accounts_file(
        tmp_path / "accounts.json",
        [role_target(ACCOUNT_A), role_target(ACCOUNT_B), role_target(ACCOUNT_C)],
    )
    sts = Mock()
    sts.assume_role.side_effect = [
        credentials(),
        ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Role assumption denied"}},
            "AssumeRole",
        ),
        credentials(),
    ]
    session_a = Mock()
    session_a.client.return_value.get_caller_identity.return_value = {"Account": ACCOUNT_A}
    session_c = Mock()
    session_c.client.return_value.get_caller_identity.return_value = {"Account": "999999999999"}

    with (
        patch("aws_security_scanner.multi_account.boto3.client", return_value=sts),
        patch("aws_security_scanner.multi_account.boto3.Session", side_effect=[session_a, session_c]),
        patch("aws_security_scanner.multi_account.run_scan", create=True) as unused_scan,
    ):
        # Pass a scan function directly so the orchestration boundary is isolated.
        scan = Mock(return_value=[sample_finding(ACCOUNT_A)])
        findings, metadata = run_multi_account_scan(
            path,
            region="eu-west-2",
            scan_function=scan,
        )

    assert len(findings) == 1
    assert scan.call_count == 1
    assert scan.call_args.kwargs["aws_session"] is session_a
    assert scan.call_args.kwargs["expected_account_id"] == ACCOUNT_A
    assert [item["status"] for item in metadata["accounts"]] == ["success", "failed", "failed"]
    assert metadata["accounts"][1]["error_code"] == "AccessDenied"
    assert "mismatch" in metadata["accounts"][2]["error_message"]
    assert metadata["summary"] == {
        "total_accounts": 3,
        "successful_accounts": 1,
        "failed_accounts": 2,
    }


def test_assumed_role_session_is_validated_before_scanning(tmp_path):
    path = write_accounts_file(tmp_path / "accounts.json", [role_target(ACCOUNT_A)])
    sts = Mock()
    sts.assume_role.return_value = credentials()
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": ACCOUNT_B}
    scan = Mock()

    with (
        patch("aws_security_scanner.multi_account.boto3.client", return_value=sts),
        patch("aws_security_scanner.multi_account.boto3.Session", return_value=session),
    ):
        findings, metadata = run_multi_account_scan(
            path,
            region="eu-west-2",
            scan_function=scan,
        )

    assert findings == []
    scan.assert_not_called()
    assert metadata["accounts"][0]["status"] == "failed"
    assert "mismatch" in metadata["accounts"][0]["error_message"]


def test_multi_account_report_metadata_is_present_in_all_formats():
    findings = [sample_finding()]
    assessment = {
        "scope": "multi-account",
        "region": "eu-west-2",
        "summary": {
            "total_accounts": 2,
            "successful_accounts": 1,
            "failed_accounts": 1,
        },
        "accounts": [
            {"account_id": ACCOUNT_A, "status": "success", "findings_count": 1},
            {
                "account_id": ACCOUNT_B,
                "status": "failed",
                "findings_count": 0,
                "error_code": "AccessDenied",
                "error_message": "Role assumption denied",
            },
        ],
    }

    json_report = build_json_report(findings, assessment_metadata=assessment)
    assert json_report["assessment"]["summary"]["failed_accounts"] == 1
    assert json_report["assessment"]["accounts"][1]["error_code"] == "AccessDenied"
    assert json_report["findings"][0]["account_id"] == ACCOUNT_A

    html = build_html_report(findings, assessment_metadata=assessment)
    assert "Assessment scope" in html
    assert ACCOUNT_B in html
    assert "Role assumption denied" in html

    sarif = build_sarif_report(findings, assessment_metadata=assessment)
    assert sarif["runs"][0]["properties"]["assessment"]["summary"]["failed_accounts"] == 1


def test_cli_accepts_accounts_file_only_as_an_explicit_option():
    args = build_parser().parse_args([
        "--source", "aws",
        "--accounts-file", "accounts.json",
        "--region", "eu-west-2",
    ])
    assert str(args.accounts_file) == "accounts.json"


def test_aws_provider_uses_injected_session_for_client_creation():
    session = Mock()
    AWSProvider(session=session, region="eu-west-2")
    called_services = {call.args[0] for call in session.client.call_args_list}
    assert {"s3", "iam", "eks", "logs", "cloudwatch", "efs", "codebuild"} <= called_services
    session.client.assert_any_call("s3", region_name="eu-west-2")
    assert not any(call.args[0] == "sts" for call in session.client.call_args_list)
