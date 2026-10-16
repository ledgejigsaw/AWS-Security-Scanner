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
    title="Lambda function URL does not require IAM authentication",
    description=(
        "The function has a Lambda Function URL configured with AuthType NONE, "
        "so the URL does not require AWS IAM authentication. Actual public "
        "reachability also depends on the function resource policy."
    ),
    remediation=(
        "Use AWS_IAM authentication unless unauthenticated URL access is an "
        "intentional application requirement. Review the resource policy and "
        "validate application authorisation and abuse protections."
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



@rule_for(
    "aws_lambda_function",
    check_id="LAMBDA-003",
    service="Lambda",
    severity=Severity.HIGH,
    category="Lifecycle Management",
    title="Lambda function uses a deprecated runtime",
    description=(
        "The configured Lambda runtime appears in the versioned AWS runtime "
        "lifecycle snapshot as deprecated. Deprecated managed runtimes may no "
        "longer receive language-runtime security updates or technical support."
    ),
    remediation=(
        "Plan and test an upgrade to a currently supported runtime. Confirm the "
        "runtime lifecycle status against the linked official AWS table before "
        "making production changes."
    ),
)
def check_lambda_deprecated_runtime(resource: Resource) -> list[Finding]:
    """Flag only known runtimes whose recorded AWS deprecation date has passed."""
    from aws_security_scanner.rules.lambda_runtime_lifecycle import (
        LAMBDA_RUNTIME_DATA_REVIEWED_ON,
        LAMBDA_RUNTIME_DATA_SOURCE,
        deprecated_runtime_date,
    )

    runtime = resource.attributes.get("runtime")
    deprecation_date = deprecated_runtime_date(runtime)
    if deprecation_date is None:
        return []
    return [
        Finding.from_rule(
            check_lambda_deprecated_runtime,
            resource=resource.resource_id,
            region=resource.region,
            evidence=(
                f"runtime={runtime}; deprecation_date={deprecation_date.isoformat()}; "
                f"lifecycle_data_reviewed_on={LAMBDA_RUNTIME_DATA_REVIEWED_ON.isoformat()}; "
                f"source={LAMBDA_RUNTIME_DATA_SOURCE}"
            ),
        )
    ]


@rule_for(
    "aws_lambda_function",
    check_id="LAMBDA-004",
    service="Lambda",
    severity=Severity.LOW,
    category="Software Supply Chain",
    title="Lambda function has no code-signing configuration",
    description=(
        "The function does not report an attached Lambda code-signing configuration. "
        "Code signing can help ensure that only trusted deployment packages are deployed, "
        "but applicability depends on the organisation's deployment model."
    ),
    remediation=(
        "Consider configuring a Lambda code-signing configuration with an approved signing "
        "profile and enforcing signature validation for deployment packages where suitable."
    ),
)
def check_lambda_code_signing_not_enforced(resource: Resource) -> list[Finding]:
    """Emit a low-severity review signal only when configuration is explicitly absent."""
    if "code_signing_config_arn" not in resource.attributes:
        return []
    if resource.attributes.get("code_signing_config_arn"):
        return []
    return [Finding.from_rule(
        check_lambda_code_signing_not_enforced,
        resource=resource.resource_id,
        region=resource.region,
        evidence="code_signing_config_arn is absent",
    )]
