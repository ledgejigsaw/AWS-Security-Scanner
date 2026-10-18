"""Opt-in read-only AWS permissions preflight.

A successful probe proves only that one representative API call succeeded;
it does not prove every action used by a service scanner is permitted.
"""
from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


# service selector: (boto service, API method, kwargs, expected IAM action)
_PROBES: dict[str, tuple[str, str, dict[str, Any], str | None]] = {
    "s3": ("s3", "list_buckets", {}, "s3:ListAllMyBuckets"),
    "iam": ("iam", "list_roles", {"MaxItems": 1}, "iam:ListRoles"),
    "ec2": ("ec2", "describe_vpcs", {"MaxResults": 5}, "ec2:DescribeVpcs"),
    "ebs": ("ec2", "describe_volumes", {"MaxResults": 5}, "ec2:DescribeVolumes"),
    "vpc": ("ec2", "describe_vpcs", {"MaxResults": 5}, "ec2:DescribeVpcs"),
    "cloudtrail": ("cloudtrail", "describe_trails", {"includeShadowTrails": False}, "cloudtrail:DescribeTrails"),
    "kms": ("kms", "list_keys", {"Limit": 1}, "kms:ListKeys"),
    "rds": ("rds", "describe_db_instances", {"MaxRecords": 20}, "rds:DescribeDBInstances"),
    "lambda": ("lambda", "list_functions", {"MaxItems": 1}, "lambda:ListFunctions"),
    "secretsmanager": ("secretsmanager", "list_secrets", {"MaxResults": 1}, "secretsmanager:ListSecrets"),
    "ecr": ("ecr", "describe_repositories", {"maxResults": 1}, "ecr:DescribeRepositories"),
    "dynamodb": ("dynamodb", "list_tables", {"Limit": 1}, "dynamodb:ListTables"),
    "sqs": ("sqs", "list_queues", {"MaxResults": 1}, "sqs:ListQueues"),
    "sns": ("sns", "list_topics", {}, "sns:ListTopics"),
    "apigateway": ("apigateway", "get_rest_apis", {"limit": 1}, "apigateway:GET"),
    "ecs": ("ecs", "list_clusters", {"maxResults": 1}, "ecs:ListClusters"),
    "cloudfront": ("cloudfront", "list_distributions", {"MaxItems": "1"}, "cloudfront:ListDistributions"),
    "waf": ("wafv2", "list_web_acls", {"Scope": "REGIONAL", "Limit": 1}, "wafv2:ListWebACLs"),
    "elb": ("elbv2", "describe_load_balancers", {"PageSize": 1}, "elasticloadbalancing:DescribeLoadBalancers"),
    "securityhub": ("securityhub", "get_findings", {"MaxResults": 1}, "securityhub:GetFindings"),
    "guardduty": ("guardduty", "list_detectors", {}, "guardduty:ListDetectors"),
    "config": ("config", "describe_configuration_recorders", {"limit": 1}, "config:DescribeConfigurationRecorders"),
    "macie": ("macie2", "get_macie_session", {}, "macie2:GetMacieSession"),
    "eks": ("eks", "list_clusters", {"maxResults": 1}, "eks:ListClusters"),
    "cloudwatch": ("logs", "describe_log_groups", {"limit": 1}, "logs:DescribeLogGroups"),
    "efs": ("efs", "describe_file_systems", {"MaxItems": 1}, "elasticfilesystem:DescribeFileSystems"),
    "codebuild": ("codebuild", "list_projects", {"sortBy": {"sortBy": "NAME", "order": "ASCENDING"}, "maxResults": 1}, "codebuild:ListProjects"),
}


def _classify_error(error: Exception) -> tuple[str, str]:
    code = ""
    if isinstance(error, ClientError):
        code = str(error.response.get("Error", {}).get("Code", ""))
    lowered = (code or type(error).__name__).lower()
    if any(term in lowered for term in ("accessdenied", "unauthorized", "notauthorized", "forbidden")):
        return "access_denied", "authorization"
    if any(term in lowered for term in ("throttl", "requestlimit", "toomanyrequests")):
        return "throttled", "throttling"
    if any(term in lowered for term in ("notenabled", "disabled", "subscriptionrequired", "invalidaccess")):
        return "disabled", "service_disabled"
    if any(term in lowered for term in ("unknownservice", "unknownoperation", "unsupported")):
        return "unsupported", "unsupported_operation"
    if isinstance(error, BotoCoreError):
        return "failed", "endpoint_or_sdk_error"
    return "failed", "probe_failed"


def run_aws_permissions_preflight(
    session: Any,
    *,
    region: str | None,
    services: list[str] | None = None,
) -> dict[str, Any]:
    """Probe one safe read-only API per selected service and preserve failures."""
    identity: dict[str, Any]
    try:
        identity_response = session.client("sts", region_name=region or "us-east-1").get_caller_identity()
        account = identity_response.get("Account") if isinstance(identity_response, dict) else None
        arn = identity_response.get("Arn") if isinstance(identity_response, dict) else None
        if not isinstance(account, str) or len(account) != 12 or not account.isdigit() or not isinstance(arn, str) or not arn:
            return {"schema_version": "1.0.0", "status": "failed", "identity": None, "checks": [], "diagnostics": ["invalid_caller_identity"]}
        identity = {"account_id": account, "principal_arn": arn}
    except Exception as exc:
        outcome, category = _classify_error(exc)
        return {"schema_version": "1.0.0", "status": "failed", "identity": None, "checks": [], "diagnostics": [category], "identity_outcome": outcome}

    selected = sorted(set(services or _PROBES))
    checks: list[dict[str, Any]] = []
    for service in selected:
        probe = _PROBES.get(service)
        if probe is None:
            checks.append({"service": service, "outcome": "unsupported", "iam_action": None, "error_category": "no_probe_defined"})
            continue
        boto_service, method_name, kwargs, iam_action = probe
        try:
            client_region = None if boto_service == "cloudfront" else region
            client = session.client(boto_service, region_name=client_region) if client_region else session.client(boto_service)
            response = getattr(client, method_name)(**kwargs)
            if service == "guardduty" and not response.get("DetectorIds"):
                outcome = "disabled"
                category = "no_detector"
            else:
                outcome = "success"
                category = None
        except Exception as exc:
            outcome, category = _classify_error(exc)
        checks.append({
            "service": service,
            "operation": method_name,
            "outcome": outcome,
            "iam_action": iam_action,
            "error_category": category,
            "scope": "global" if service == "cloudfront" else (region or "configured-region"),
        })
    incomplete = any(item["outcome"] not in {"success"} for item in checks)
    return {
        "schema_version": "1.0.0",
        "status": "incomplete" if incomplete else "complete",
        "identity": identity,
        "checks": checks,
        "limitations": [
            "Each service is checked with one representative read-only API only.",
            "Success does not prove every discovery API or optional integration permission is granted.",
            "Access denied, disabled services, and unsupported probes are coverage gaps, not zero-resource results.",
        ],
    }
