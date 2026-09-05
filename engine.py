from collections.abc import Callable

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.models.resource import Resource


Rule = Callable[[Resource], list[Finding]]


class RuleEngine:
    """Execute security rules against normalised resources."""

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def scan(self, resources: list[Resource]) -> list[Finding]:
        """Run applicable security rules against resources."""

        findings = []

        for resource in resources:
            for rule in self.rules:
                if rule.resource_type != resource.resource_type:
                    continue

                findings.extend(rule(resource))

        return findings 