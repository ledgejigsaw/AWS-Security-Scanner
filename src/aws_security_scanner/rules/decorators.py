from collections.abc import Callable
from typing import Any


def rule_for(resource_type: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare the AWS resource type a security rule applies to."""

    def decorator(rule: Callable[..., Any]) -> Callable[..., Any]:
        rule.resource_type = resource_type
        return rule

    return decorator