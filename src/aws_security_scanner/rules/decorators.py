from collections.abc import Callable
from typing import Any

from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.rule import RuleMetadata


def rule_for(
    resource_type: str,
    *,
    check_id: str,
    service: str,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    remediation: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare the resource type and metadata for a security rule."""

    def decorator(
        rule: Callable[..., Any],
    ) -> Callable[..., Any]:
        rule.resource_type = resource_type

        rule.metadata = RuleMetadata(
            check_id=check_id,
            service=service,
            resource_type=resource_type,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
        )

        return rule

    return decorator