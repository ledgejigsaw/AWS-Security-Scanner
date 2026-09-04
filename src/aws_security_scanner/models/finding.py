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