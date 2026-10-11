import json
from typing import Any

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


def _policy_document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _allows_wildcard_secret_access(policy: Any) -> bool:
    document = _policy_document(policy)
    if not document:
        return False

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    sensitive_actions = {
        "secretsmanager:getsecretvalue",
        "secretsmanager:describesecret",
        "secretsmanager:*",
        "*",
    }

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if principal == "*":
            wildcard_principal = True
        elif isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            wildcard_principal = aws_principal == "*" or (
                isinstance(aws_principal, list) and "*" in aws_principal
            )
        else:
            wildcard_principal = False
        if not wildcard_principal:
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue

        if any(
            isinstance(action, str)
            and (
                action.lower() in sensitive_actions
            )
            for action in actions
        ) and not statement.get("Condition"):
            return True

    return False


@rule_for(
    "aws_secretsmanager_secret",
    check_id="SM-001",
    service="Secrets Manager",
    severity=Severity.MEDIUM,
    category="Credential Hygiene",
    title="Secrets Manager secret rotation is disabled",
    description=(
        "The secret is explicitly configured without automatic rotation. "
        "Rotation can reduce the useful lifetime of exposed credentials, "
        "but applicability depends on the secret type and application design."
    ),
    remediation=(
        "Enable and configure rotation where supported and operationally "
        "appropriate. Verify the rotation function, dependent applications "
        "and recovery procedure before enabling it."
    ),
)
def check_secret_rotation_disabled(resource: Resource) -> list[Finding]:
    """Detect secrets whose rotation is explicitly disabled."""
    if resource.attributes.get("rotation_enabled") is not False:
        return []

    return [
        Finding.from_rule(
            check_secret_rotation_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="rotation_enabled=false",
        )
    ]


@rule_for(
    "aws_secretsmanager_secret",
    check_id="SM-002",
    service="Secrets Manager",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="Secrets Manager resource policy grants wildcard access",
    description=(
        "The secret resource policy contains an unconditional Allow statement "
        "with a wildcard principal and a sensitive Secrets Manager action. "
        "This can permit unintended identities to retrieve or inspect the secret."
    ),
    remediation=(
        "Restrict resource-policy principals to the intended AWS account, "
        "roles or services. Add narrowly scoped conditions where required, "
        "and validate the resulting policy with the secret's legitimate consumers."
    ),
)
def check_secret_wildcard_resource_policy(resource: Resource) -> list[Finding]:
    """Detect unconditional wildcard-principal access in a secret resource policy."""
    if not _allows_wildcard_secret_access(
        resource.attributes.get("resource_policy")
    ):
        return []

    return [
        Finding.from_rule(
            check_secret_wildcard_resource_policy,
            resource=resource.resource_id,
            region=resource.region,
            evidence=(
                "resource_policy allows wildcard principal to perform "
                "sensitive Secrets Manager actions without a condition"
            ),
        )
    ]
