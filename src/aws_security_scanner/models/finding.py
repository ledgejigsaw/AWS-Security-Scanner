from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check_id: str
    severity: Severity
    service: str
    resource: str
    title: str
    description: str
    remediation: str
    region: str | None = None
    evidence: str | None = None

    @classmethod
    def from_rule(
        cls,
        rule,
        *,
        resource: str,
        region: str | None = None,
        evidence: str | None = None,
    ) -> "Finding":
        """Create a finding from a rule's metadata."""

        metadata = rule.metadata

        return cls(
            check_id=metadata.check_id,
            severity=metadata.severity,
            service=metadata.service,
            resource=resource,
            title=metadata.title,
            description=metadata.description,
            remediation=metadata.remediation,
            region=region,
            evidence=evidence,
        )