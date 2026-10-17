"""Conservative static analysis for IAM policy statement context.

This is not an AWS effective-permissions simulator. It records policy-source
context and marks conditional or incomplete conclusions for review.
"""
from __future__ import annotations

import fnmatch
import json
from typing import Any

_HIGH_RISK_ACTIONS = (
    "iam:PassRole", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey", "sts:AssumeRole", "organizations:UpdatePolicy",
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _matches(patterns: list[Any], value: str) -> bool:
    return any(isinstance(pattern, str) and fnmatch.fnmatchcase(value.lower(), pattern.lower()) for pattern in patterns)


def analyze_iam_policy(
    policy_document: dict[str, Any] | str,
    *,
    policy_source: str = "unspecified",
) -> dict[str, Any]:
    """Return statement-level observations without asserting effective access.

    ``policy_source`` should identify the observed context (for example,
    identity_policy, resource_policy, permissions_boundary, session_policy, or
    service_control_policy). Multiple sources must be evaluated together by a
    caller; this function deliberately does not combine them into an allow/deny
    decision.
    """
    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except (TypeError, json.JSONDecodeError):
            return {"policy_source": policy_source, "status": "invalid", "diagnostics": ["policy_document_invalid_json"], "statements": []}
    if not isinstance(policy_document, dict):
        return {"policy_source": policy_source, "status": "invalid", "diagnostics": ["policy_document_not_object"], "statements": []}

    raw_statements = policy_document.get("Statement", [])
    statements = _as_list(raw_statements)
    results: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            diagnostics.append(f"statement_{index}_not_object")
            continue
        effect = statement.get("Effect")
        actions = _as_list(statement.get("Action"))
        not_actions = _as_list(statement.get("NotAction"))
        resources = _as_list(statement.get("Resource"))
        not_resources = _as_list(statement.get("NotResource"))
        principal = statement.get("Principal", statement.get("NotPrincipal"))
        conditions = statement.get("Condition")
        flags: list[str] = []
        if effect not in {"Allow", "Deny"}:
            flags.append("invalid_or_missing_effect")
        if statement.get("Action") == "*" or _matches(actions, "*"):
            flags.append("wildcard_action")
        if any(isinstance(item, str) and "*" in item for item in actions):
            flags.append("pattern_action")
        if not_actions:
            flags.append("not_action_requires_contextual_review")
        if any(item == "*" for item in resources) or any(isinstance(item, str) and item == "*" for item in resources):
            flags.append("wildcard_resource")
        if not_resources:
            flags.append("not_resource_requires_contextual_review")
        if principal == "*" or (isinstance(principal, dict) and any(value == "*" or isinstance(value, list) and "*" in value for value in principal.values())):
            flags.append("wildcard_principal")
        matched_high_risk = sorted(action for action in _HIGH_RISK_ACTIONS if _matches(actions, action))
        if matched_high_risk:
            flags.append("high_risk_iam_or_sts_action")
        if conditions:
            flags.append("condition_requires_evaluation")
        if effect == "Deny":
            status = "explicit_deny_statement"
        elif effect == "Allow" and conditions:
            status = "conditional_allow_requires_evaluation"
        elif effect == "Allow" and ("wildcard_action" in flags or "wildcard_resource" in flags or "wildcard_principal" in flags or "high_risk_iam_or_sts_action" in flags):
            status = "broad_or_high_risk_allow_review"
        elif effect == "Allow" and (not_actions or not_resources):
            status = "context_dependent_allow_review"
        elif effect == "Allow":
            status = "allow_statement_observed"
        else:
            status = "indeterminate"
        results.append({
            "statement_index": index,
            "policy_source": policy_source,
            "effect": effect if isinstance(effect, str) else None,
            "actions": [item for item in actions if isinstance(item, str)],
            "not_actions": [item for item in not_actions if isinstance(item, str)],
            "resources": [item for item in resources if isinstance(item, str)],
            "not_resources": [item for item in not_resources if isinstance(item, str)],
            "principal_present": principal is not None,
            "condition_present": bool(conditions),
            "high_risk_actions": matched_high_risk,
            "flags": sorted(set(flags)),
            "status": status,
        })
    if not isinstance(raw_statements, (list, dict)):
        diagnostics.append("statement_collection_invalid")
    return {
        "policy_source": policy_source,
        "status": "analysed_with_diagnostics" if diagnostics else "analysed",
        "diagnostics": sorted(diagnostics),
        "statements": results,
        "limitations": [
            "This result describes one policy document, not effective permissions.",
            "Explicit deny, principal, condition, boundary, session-policy and SCP interactions require full context.",
            "Policy variables and AWS-specific condition semantics are not evaluated here.",
        ],
    }
