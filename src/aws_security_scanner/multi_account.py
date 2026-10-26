"""Sequential, opt-in cross-account AWS assessment orchestration.

Credentials are assumed in memory only. This module intentionally accepts an
explicit, bounded target list and does not discover accounts through Organizations.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import boto3
from botocore.exceptions import ClientError

from aws_security_scanner.models.finding import Finding


_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_ROLE_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$"
)
_MAX_ACCOUNTS = 100


def load_account_targets(path: str | Path) -> list[dict[str, str]]:
    """Load and validate a bounded JSON list of explicit role targets."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read accounts file '{source}': {error}") from error

    if not isinstance(payload, dict) or set(payload) != {"accounts"}:
        raise ValueError("Accounts file must be a JSON object containing only an 'accounts' array.")
    accounts = payload.get("accounts")
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= _MAX_ACCOUNTS:
        raise ValueError(f"'accounts' must contain between 1 and {_MAX_ACCOUNTS} entries.")

    targets: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(accounts):
        context = f"accounts[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{context} must be an object.")
        if set(item) - {"account_id", "role_arn", "external_id"}:
            raise ValueError(f"{context} contains unsupported fields.")
        account_id = item.get("account_id")
        role_arn = item.get("role_arn")
        external_id = item.get("external_id")
        if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
            raise ValueError(f"{context}.account_id must be a 12-digit AWS account ID.")
        match = _ROLE_ARN.fullmatch(role_arn) if isinstance(role_arn, str) else None
        if match is None:
            raise ValueError(f"{context}.role_arn must be an IAM role ARN.")
        if match.group(1) != account_id:
            raise ValueError(f"{context}.role_arn account ID must match account_id.")
        if account_id in seen_ids:
            raise ValueError(f"Duplicate account_id '{account_id}' in accounts file.")
        if external_id is not None and (
            not isinstance(external_id, str) or not external_id.strip() or len(external_id) > 1224
        ):
            raise ValueError(f"{context}.external_id must be non-empty text of at most 1224 characters.")
        target = {"account_id": account_id, "role_arn": role_arn}
        if external_id is not None:
            target["external_id"] = external_id
        targets.append(target)
        seen_ids.add(account_id)
    return targets


def run_multi_account_scan(
    accounts_file: str | Path,
    *,
    region: str | None,
    scan_function: Callable[..., list[Finding]],
    policy_path: Path | None = None,
    include_native_findings: bool = False,
    native_findings_limit: int = 100,
    guardduty_regions: list[str] | None = None,
    guardduty_record_state: str = "ALL",
    guardduty_updated_after: str | None = None,
    guardduty_finding_types: list[str] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Assume each configured role sequentially and record every account outcome."""
    targets = load_account_targets(accounts_file)
    caller_sts = boto3.client("sts", region_name=region)
    findings: list[Finding] = []
    account_results: list[dict[str, Any]] = []

    for target in targets:
        account_id = target["account_id"]
        try:
            request: dict[str, str] = {
                "RoleArn": target["role_arn"],
                "RoleSessionName": f"aws-security-scanner-{account_id}",
            }
            if target.get("external_id") is not None:
                request["ExternalId"] = target["external_id"]
            response = caller_sts.assume_role(**request)
            credentials = response.get("Credentials")
            if not isinstance(credentials, dict):
                raise RuntimeError("STS AssumeRole response did not contain credentials.")
            access_key = credentials.get("AccessKeyId")
            secret_key = credentials.get("SecretAccessKey")
            session_token = credentials.get("SessionToken")
            if not all(isinstance(value, str) and value for value in (access_key, secret_key, session_token)):
                raise RuntimeError("STS AssumeRole response contained incomplete credentials.")

            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region,
            )
            identity = session.client("sts", region_name=region).get_caller_identity()
            actual_account_id = identity.get("Account") if isinstance(identity, dict) else None
            if actual_account_id != account_id:
                raise RuntimeError(
                    f"Assumed identity account mismatch: expected {account_id}, got {actual_account_id!r}."
                )

            account_findings = scan_function(
                "aws",
                policy_path=policy_path,
                region=region,
                include_native_findings=include_native_findings,
                native_findings_limit=native_findings_limit,
                guardduty_regions=guardduty_regions,
                guardduty_record_state=guardduty_record_state,
                guardduty_updated_after=guardduty_updated_after,
                guardduty_finding_types=guardduty_finding_types,
                aws_session=session,
                expected_account_id=account_id,
            )
            findings.extend(account_findings)
            account_results.append({
                "account_id": account_id,
                "status": "success",
                "findings_count": len(account_findings),
            })
        except Exception as error:
            result: dict[str, Any] = {
                "account_id": account_id,
                "status": "failed",
                "findings_count": 0,
                "error_type": type(error).__name__,
            }
            if isinstance(error, ClientError):
                error_details = error.response.get("Error", {})
                if isinstance(error_details, dict):
                    code = error_details.get("Code")
                    message = error_details.get("Message")
                    if isinstance(code, str):
                        result["error_code"] = code
                    if isinstance(message, str) and message:
                        result["error_message"] = message[:300]
            else:
                message = str(error)
                if message:
                    result["error_message"] = message[:300]
            account_results.append(result)

    successful = sum(item["status"] == "success" for item in account_results)
    failed = len(account_results) - successful
    metadata: dict[str, Any] = {
        "scope": "multi-account",
        "region": region,
        "summary": {
            "total_accounts": len(account_results),
            "successful_accounts": successful,
            "failed_accounts": failed,
        },
        "accounts": account_results,
    }
    return findings, metadata
