from collections import Counter
from dataclasses import dataclass

from aws_security_scanner.models.finding import Finding


@dataclass
class ScanSummary:
    """Summary statistics for a security scan."""

    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int

    @property
    def by_severity(self) -> dict[str, int]:
        """Return finding counts grouped by severity."""

        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
            "INFO": self.info,
        }


def build_summary(findings: list[Finding]) -> ScanSummary:
    """Build summary statistics from security findings."""

    counts = Counter(
        finding.severity.value
        for finding in findings
    )

    return ScanSummary(
        total_findings=len(findings),
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        info=counts["INFO"],
    )