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


def _allows_unconditional_wildcard(policy: Any, service: str, actions_of_interest: set[str]) -> bool:
    document = _policy_document(policy)
    if not document:
        return False
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    service_prefix = service.lower() + ":"
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            wildcard = True
        elif isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            wildcard = aws_principal == "*" or (
                isinstance(aws_principal, list) and "*" in aws_principal
            )
        else:
            wildcard = False
        if not wildcard or statement.get("Condition"):
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        for action in actions:
            if not isinstance(action, str):
                continue
            normalized = action.lower()
            if normalized in {"*", f"{service_prefix}*"} or normalized in actions_of_interest:
                return True
    return False


@rule_for(
    "aws_sqs_queue",
    check_id="SQS-001",
    service="SQS",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="SQS queue policy grants wildcard access",
    description=(
        "The queue policy contains an unconditional Allow statement with a wildcard "
        "principal and a queue-sensitive action. This can expose message contents "
        "or permit untrusted publishers to inject messages."
    ),
    remediation=(
        "Restrict queue-policy principals to the required AWS accounts, roles or "
        "services. Review SendMessage, ReceiveMessage, DeleteMessage and wildcard "
        "permissions, and add narrow conditions where appropriate."
    ),
)
def check_sqs_public_access_policy(resource: Resource) -> list[Finding]:
    """Flag unconditional wildcard access to sensitive SQS queue actions."""
    actions = {
        "sqs:sendmessage", "sqs:receivemessage", "sqs:deletemessage",
        "sqs:deletemessagebatch", "sqs:receivemessagebatch", "sqs:*", "*",
    }
    if not _allows_unconditional_wildcard(resource.attributes.get("policy"), "sqs", actions):
        return []
    return [Finding.from_rule(
        check_sqs_public_access_policy,
        resource=resource.resource_id,
        region=resource.region,
        evidence="queue policy allows an unconditional wildcard principal to perform sensitive SQS actions",
    )]


@rule_for(
    "aws_sqs_queue",
    check_id="SQS-002",
    service="SQS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="SQS queue server-side encryption is disabled",
    description=(
        "Complete queue metadata explicitly indicates that neither SQS-managed "
        "server-side encryption nor a KMS key is configured. Message bodies and "
        "attributes may therefore not be encrypted at rest by SQS."
    ),
    remediation=(
        "Enable SQS-managed server-side encryption or configure an appropriate "
        "AWS KMS key, then verify key policy and operational requirements."
    ),
)
def check_sqs_encryption_disabled(resource: Resource) -> list[Finding]:
    """Flag queues only when discovery explicitly normalises encryption as disabled."""
    if resource.attributes.get("encryption_enabled") is not False:
        return []
    return [Finding.from_rule(
        check_sqs_encryption_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence="encryption_enabled=false",
    )]


@rule_for(
    "aws_sns_topic",
    check_id="SNS-001",
    service="SNS",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="SNS topic policy grants wildcard publish or subscribe access",
    description=(
        "The topic policy contains an unconditional Allow statement with a wildcard "
        "principal and a sensitive publish/subscribe action. This may permit "
        "untrusted message publication or unintended subscription access."
    ),
    remediation=(
        "Restrict topic-policy principals and actions to approved publishers and "
        "subscribers. Add narrowly scoped conditions and review cross-account access."
    ),
)
def check_sns_public_access_policy(resource: Resource) -> list[Finding]:
    """Flag unconditional wildcard access to sensitive SNS topic actions."""
    actions = {"sns:publish", "sns:subscribe", "sns:*", "*"}
    if not _allows_unconditional_wildcard(resource.attributes.get("policy"), "sns", actions):
        return []
    return [Finding.from_rule(
        check_sns_public_access_policy,
        resource=resource.resource_id,
        region=resource.region,
        evidence="topic policy allows an unconditional wildcard principal to publish or subscribe",
    )]


@rule_for(
    "aws_sns_topic",
    check_id="SNS-002",
    service="SNS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="SNS topic server-side encryption is disabled",
    description=(
        "Complete topic metadata explicitly indicates that no AWS KMS key is "
        "configured for server-side encryption. Messages published to the topic "
        "may therefore not be encrypted at rest by SNS."
    ),
    remediation=(
        "Configure an appropriate AWS KMS key for the topic and verify the key "
        "policy grants the SNS service and authorised publishers the required access."
    ),
)
def check_sns_encryption_disabled(resource: Resource) -> list[Finding]:
    """Flag topics only when discovery explicitly normalises encryption as disabled."""
    if resource.attributes.get("encryption_enabled") is not False:
        return []
    return [Finding.from_rule(
        check_sns_encryption_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence="encryption_enabled=false",
    )]
