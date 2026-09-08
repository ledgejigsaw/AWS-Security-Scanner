from collections.abc import Callable

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.policy import SecurityPolicy


Rule = Callable[[Resource], list[Finding]]


class RuleEngine:
    """Execute security rules against normalised resources."""

    def __init__(
        self,
        rules: list[Rule],
        policy: SecurityPolicy | None = None,
    ):
        self.rules = rules
        self.policy = policy or SecurityPolicy()

    def scan(self, resources: list[Resource]) -> list[Finding]:
        """Run enabled security rules against resources."""

        findings = []

        for resource in resources:
            for rule in self.rules:
                if rule.resource_type != resource.resource_type:
                    continue

                check_id = rule.metadata.check_id

                if not self.policy.is_enabled(check_id):
                    continue

                findings.extend(rule(resource))

        return findings