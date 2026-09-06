from dataclasses import dataclass

from aws_security_scanner.models.finding import Severity


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata describing a security rule."""

    check_id: str
    service: str
    resource_type: str
    severity: Severity
    category: str
    title: str
    description: str
    remediation: str