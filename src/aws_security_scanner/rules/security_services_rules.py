"""Rules for regional AWS-native security-service posture."""

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_securityhub_hub",
    check_id="SECURITYHUB-001",
    service="Security Hub",
    severity=Severity.MEDIUM,
    category="Detection and Monitoring",
    title="AWS Security Hub is not enabled in this region",
    description="Security Hub was explicitly reported as not enabled in the assessed AWS region. This reduces centralised security-posture aggregation and control evaluation in that region.",
    remediation="Review the region's security-monitoring requirements and enable AWS Security Hub where required. Confirm standards and controls are configured appropriately after enablement.",
)
def check_security_hub_disabled(resource: Resource) -> list[Finding]:
    """Report Security Hub when the provider explicitly observes it disabled."""
    if resource.attributes.get("enabled") is not False:
        return []
    return [
        Finding.from_rule(
            check_security_hub_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="Security Hub DescribeHub returned ResourceNotFoundException",
        )
    ]


@rule_for(
    "aws_guardduty_detector",
    check_id="GUARDDUTY-001",
    service="GuardDuty",
    severity=Severity.HIGH,
    category="Detection and Monitoring",
    title="Amazon GuardDuty is not enabled in this region",
    description="No GuardDuty detector was found in the assessed AWS region. Threat detection coverage may therefore be absent for supported data sources in that region.",
    remediation="Review regional threat-detection requirements and enable GuardDuty where required. Configure data sources and delegated-administrator settings as appropriate.",
)
def check_guardduty_disabled(resource: Resource) -> list[Finding]:
    """Report GuardDuty only when the provider explicitly observes it disabled."""
    if resource.attributes.get("enabled") is not False:
        return []
    return [
        Finding.from_rule(
            check_guardduty_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="GuardDuty ListDetectors returned no detector IDs",
        )
    ]
