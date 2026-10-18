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


def analyze_resource_policy_context(
    policies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyse supplied resource-policy documents without returning raw JSON."""
    results = []
    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            results.append({"index": index, "status": "unknown", "diagnostic": "policy_record_invalid"})
            continue
        resource_id = policy.get("resource_id")
        document = policy.get("policy_document")
        if not isinstance(document, (dict, str)):
            results.append({
                "resource_id": resource_id if isinstance(resource_id, str) else None,
                "status": "unknown",
                "diagnostic": "policy_document_unavailable",
            })
            continue
        analysis = analyze_iam_policy(document, policy_source="resource_policy")
        results.append({
            "resource_id": resource_id if isinstance(resource_id, str) else None,
            "status": analysis["status"],
            "analysis": analysis,
        })
    return {
        "schema_version": "1.0.0",
        "status": "partial" if any(item["status"] == "unknown" for item in results) else "complete",
        "policies": sorted(results, key=lambda item: (item.get("resource_id") or "", item["status"])),
        "limitations": [
            "Resource policy statements are analysed independently from identity policies and permissions boundaries.",
            "The resource identifier is a correlation label only; no effective-access decision is inferred.",
        ],
    }


def collect_scp_context(
    organizations_client: Any,
    target_ids: list[str],
) -> dict[str, Any]:
    """Collect SCPs attached to caller-supplied account, OU, or root targets.

    Organizations is optional and may be unavailable to member accounts. A
    denied call is reported as unknown context, never as an empty SCP set.
    """
    policies: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for target_id in sorted(set(target_ids)):
        if not isinstance(target_id, str) or not target_id:
            continue
        try:
            attached = _next_token_pages(
                organizations_client, "list_policies_for_target", "Policies",
                TargetId=target_id, Filter="SERVICE_CONTROL_POLICY",
            )
        except Exception as exc:
            failures.append({"target_id": target_id, "operation": "list_policies_for_target", "outcome": _error_category(exc)})
            continue
        for policy in attached:
            policy_id = policy.get("Id")
            if not isinstance(policy_id, str) or not policy_id:
                continue
            try:
                response = organizations_client.describe_policy(PolicyId=policy_id)
                policy_data = response.get("Policy", {}).get("Content")
                if not isinstance(policy_data, (str, dict)):
                    raise ValueError("SCP content unavailable")
                policies.append({
                    "target_id": target_id,
                    "policy_id": policy_id,
                    "name": policy.get("Name"),
                    "analysis": analyze_iam_policy(policy_data, policy_source="service_control_policy"),
                    "status": "complete",
                })
            except Exception as exc:
                failures.append({"target_id": target_id, "operation": "describe_policy", "outcome": _error_category(exc)})
                policies.append({
                    "target_id": target_id, "policy_id": policy_id,
                    "name": policy.get("Name"), "analysis": None, "status": "unknown",
                })
    return {
        "schema_version": "1.0.0",
        "status": "partial" if failures else "complete",
        "policies": sorted(policies, key=lambda item: (item["target_id"], item["policy_id"])),
        "failures": sorted(failures, key=lambda item: (item["target_id"], item["operation"])),
        "limitations": [
            "Only the target IDs explicitly supplied by the caller are inspected.",
            "SCP analysis is static statement context and does not calculate effective permissions.",
        ],
    }


def _next_token_pages(
    client: Any,
    method_name: str,
    result_key: str,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Collect Organizations NextToken pages with loop and shape checks."""
    method = getattr(client, method_name)
    token = None
    results: list[dict[str, Any]] = []
    while True:
        request = dict(kwargs)
        if token:
            request["NextToken"] = token
        response = method(**request)
        values = response.get(result_key, [])
        if isinstance(values, list):
            results.extend(item for item in values if isinstance(item, dict))
        next_token = response.get("NextToken")
        if not next_token:
            return results
        if next_token == token:
            raise RuntimeError(f"{method_name} returned a repeated continuation token")
        token = next_token
