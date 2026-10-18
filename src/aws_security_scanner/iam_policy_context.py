"""Collect IAM policy context without claiming effective permissions."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from aws_security_scanner.iam_analysis import analyze_iam_policy


def _pages(client: Any, method_name: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Collect marker-paginated IAM API results and fail on repeated markers."""
    method = getattr(client, method_name)
    marker = None
    results: list[Any] = []
    while True:
        request = dict(kwargs)
        if marker:
            request["Marker"] = marker
        response = method(**request)
        values = response.get(result_key, [])
        if isinstance(values, list):
            results.extend(values)
        if not response.get("IsTruncated"):
            break
        next_marker = response.get("Marker")
        if not next_marker or next_marker == marker:
            raise RuntimeError(f"{method_name} returned incomplete pagination")
        marker = next_marker
    return results


def _error_category(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return "access_denied"
        if "Throttl" in code or code == "RequestLimitExceeded":
            return "throttled"
    return "failed"


def _policy_document(iam_client: Any, policy_arn: str) -> dict[str, Any]:
    policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
    version_id = policy.get("DefaultVersionId")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError("IAM policy has no default version ID")
    version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get("PolicyVersion", {})
    document = version.get("Document")
    if not isinstance(document, (dict, str)):
        raise ValueError("IAM policy version has no readable document")
    if isinstance(document, dict):
        return document
    import json
    parsed = json.loads(document)
    if not isinstance(parsed, dict):
        raise ValueError("IAM policy document is not an object")
    return parsed


def collect_iam_policy_context(iam_client: Any) -> dict[str, Any]:
    """Inventory users, groups, and roles with attached/inline policy context.

    Per-entity API failures are represented as unknown context. Policy document
    content is reduced through the existing static analyzer before it is
    returned; raw credential or policy responses are not copied into output.
    """
    entities: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []

    entity_specs = (
        ("user", "list_users", "Users", "UserName", "list_attached_user_policies", "list_user_policies", "UserName"),
        ("group", "list_groups", "Groups", "GroupName", "list_attached_group_policies", "list_group_policies", "GroupName"),
        ("role", "list_roles", "Roles", "RoleName", "list_attached_role_policies", "list_role_policies", "RoleName"),
    )

    try:
        for entity_type, list_method, result_key, name_key, attached_method, inline_method, entity_arg in entity_specs:
            try:
                discovered = _pages(iam_client, list_method, result_key)
            except Exception as exc:
                failures.append({"entity_type": entity_type, "operation": list_method, "outcome": _error_category(exc)})
                continue

            for entity in discovered:
                if not isinstance(entity, dict):
                    continue
                name = entity.get(name_key)
                if not isinstance(name, str) or not name:
                    continue
                entry: dict[str, Any] = {
                    "entity_type": entity_type,
                    "name": name,
                    "arn": entity.get("Arn"),
                    "permissions_boundary_present": bool(entity.get("PermissionsBoundary")),
                    "permissions_boundary_arn": (entity.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                    "attached_policies": [],
                    "inline_policies": [],
                    "trust_policy": None,
                    "status": "complete",
                }
                if entity_type == "role":
                    trust = entity.get("AssumeRolePolicyDocument")
                    if isinstance(trust, dict):
                        entry["trust_policy"] = analyze_iam_policy(trust, policy_source="role_trust_policy")

                for policy_method, inline in ((attached_method, False), (inline_method, True)):
                    try:
                        if inline:
                            names = _pages(iam_client, policy_method, "PolicyNames", **{entity_arg: name})
                            policies = [{"PolicyName": item} for item in names if isinstance(item, str)]
                        else:
                            policies = _pages(iam_client, policy_method, "AttachedPolicies", **{entity_arg: name})
                    except Exception as exc:
                        entry["status"] = "partial"
                        failures.append({"entity_type": entity_type, "operation": policy_method, "outcome": _error_category(exc)})
                        continue

                    for policy in policies:
                        policy_name = policy.get("PolicyName")
                        policy_arn = policy.get("PolicyArn")
                        target = entry["inline_policies"] if inline else entry["attached_policies"]
                        record: dict[str, Any] = {"name": policy_name, "arn": policy_arn}
                        if inline:
                            try:
                                response = getattr(iam_client, f"get_{entity_type}_policy")(**{entity_arg: name, "PolicyName": policy_name})
                                document = response.get("PolicyDocument")
                                if isinstance(document, (dict, str)):
                                    record["analysis"] = analyze_iam_policy(document, policy_source="inline_identity_policy")
                                else:
                                    record["status"] = "unknown_document"
                            except Exception as exc:
                                record["status"] = _error_category(exc)
                                entry["status"] = "partial"
                        elif isinstance(policy_arn, str):
                            try:
                                record["analysis"] = analyze_iam_policy(_policy_document(iam_client, policy_arn), policy_source="managed_identity_policy")
                            except Exception as exc:
                                record["status"] = _error_category(exc)
                                entry["status"] = "partial"
                        target.append(record)
                entities.append(entry)

    except Exception as exc:
        failures.append({"entity_type": "inventory", "operation": "collect_iam_policy_context", "outcome": _error_category(exc)})

    return {
        "schema_version": "1.0.0",
        "status": "partial" if failures or any(item["status"] != "complete" for item in entities) else "complete",
        "entity_count": len(entities),
        "entities": sorted(entities, key=lambda item: (item["entity_type"], item["name"])),
        "failures": sorted(failures, key=lambda item: (item["entity_type"], item["operation"], item["outcome"])),
        "limitations": [
            "This is inventory and static policy context, not an effective-permissions calculation.",
            "Organizations SCPs, session policies, resource policies, service control interactions, and runtime conditions may change effective access.",
            "A missing policy document caused by access denial is unknown, not an empty policy.",
        ],
    }
