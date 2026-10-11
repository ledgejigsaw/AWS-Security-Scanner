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


def _has_unconditional_wildcard_invoke(policy: Any) -> bool:
    document = _policy_document(policy)
    if not document:
        return False

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

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
        invokes = any(
            isinstance(action, str)
            and action.lower() in {"lambda:invokefunction", "lambda:*", "*"}
            for action in actions
        )
        if invokes and not statement.get("Condition"):
            return True

    return False


@rule_for(
    "aws_lambda_function",
    check_id="LAMBDA-001",
    service="Lambda",
    severity=Severity.HIGH,
    category="Network Exposure",
    title="Lambda function URL allows unauthenticated requests",
    description=(
        "The function has a Lambda Function URL configured with AuthType NONE. "
        "Requests to the URL do not require AWS IAM authentication; any "
        "additional resource-policy conditions should be reviewed separately."
    ),
    remediation=(
        "Use AWS_IAM authentication unless unauthenticated access is an "
        "intentional application requirement. If public access is required, "
        "validate input handling, authorisation and abuse protections."
    ),
)
def check_lambda_public_function_url(resource: Resource) -> list[Finding]:
    """Detect Lambda Function URLs explicitly configured without IAM auth."""
    if resource.attributes.get("function_url_auth_type") != "NONE":
        return []

    return [
        Finding.from_rule(
            check_lambda_public_function_url,
            resource=resource.resource_id,
            region=resource.region,
            evidence="function_url_auth_type=NONE",
        )
    ]


@rule_for(
    "aws_lambda_function",
    check_id="LAMBDA-002",
    service="Lambda",
    severity=Severity.HIGH,
    category="Access Control",
    title="Lambda resource policy permits wildcard invocation",
    description=(
        "The function resource policy contains an unconditional Allow statement "
        "with a wildcard principal and broad Lambda invocation action. This "
        "can permit unintended callers to invoke the function."
    ),
    remediation=(
        "Restrict the principal to the intended AWS account, role, service or "
        "organisation. Where public invocation is intentional, document the "
        "design and enforce application-level authorisation and abuse controls."
    ),
)
def check_lambda_wildcard_invoke_policy(resource: Resource) -> list[Finding]:
    """Detect unconditional wildcard-principal Lambda invocation permissions."""
    if not _has_unconditional_wildcard_invoke(
        resource.attributes.get("resource_policy")
    ):
        return []

    return [
        Finding.from_rule(
            check_lambda_wildcard_invoke_policy,
            resource=resource.resource_id,
            region=resource.region,
            evidence="resource_policy allows wildcard principal to invoke function without a condition",
        )
    ]
