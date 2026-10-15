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


@rule_for(
    "aws_config_service",
    check_id="CONFIG-001",
    service="AWS Config",
    severity=Severity.MEDIUM,
    category="Detection and Monitoring",
    title="AWS Config configuration recorder is not configured",
    description="No AWS Config configuration recorder was observed in the assessed region, so resource configuration history and configuration-rule evaluation may be unavailable.",
    remediation="Review the region's configuration-auditing requirements and configure an AWS Config recorder and delivery channel where required.",
)
def check_config_recorder_missing(resource: Resource) -> list[Finding]:
    """Report AWS Config only when discovery explicitly observes no recorder."""
    if resource.attributes.get("recorder_configured") is not False:
        return []
    return [
        Finding.from_rule(
            check_config_recorder_missing,
            resource=resource.resource_id,
            region=resource.region,
            evidence="AWS Config DescribeConfigurationRecorders returned no recorders",
        )
    ]


@rule_for(
    "aws_config_service",
    check_id="CONFIG-002",
    service="AWS Config",
    severity=Severity.HIGH,
    category="Detection and Monitoring",
    title="AWS Config configuration recorder is not recording",
    description="AWS Config has a configured recorder, but discovery explicitly reports that it is not recording. Configuration history may therefore be incomplete.",
    remediation="Investigate the recorder status and resume recording after confirming the required delivery channel and permissions.",
)
def check_config_recorder_stopped(resource: Resource) -> list[Finding]:
    """Report a stopped recorder only when AWS explicitly reports recording=False."""
    if resource.attributes.get("recording") is not False:
        return []
    return [
        Finding.from_rule(
            check_config_recorder_stopped,
            resource=resource.resource_id,
            region=resource.region,
            evidence="AWS Config DescribeConfigurationRecorderStatus reported recording=false",
        )
    ]


@rule_for(
    "aws_config_service",
    check_id="CONFIG-003",
    service="AWS Config",
    severity=Severity.MEDIUM,
    category="Detection and Monitoring",
    title="AWS Config delivery channel is not configured",
    description="No AWS Config delivery channel was observed in the assessed region. Configuration snapshots and notifications may not be delivered as expected.",
    remediation="Review the required AWS Config delivery design and configure an appropriate delivery channel if the service is required in this region.",
)
def check_config_delivery_channel_missing(resource: Resource) -> list[Finding]:
    """Report a missing delivery channel only when discovery explicitly observes none."""
    if resource.attributes.get("delivery_channel_configured") is not False:
        return []
    return [
        Finding.from_rule(
            check_config_delivery_channel_missing,
            resource=resource.resource_id,
            region=resource.region,
            evidence="AWS Config DescribeDeliveryChannels returned no delivery channels",
        )
    ]


@rule_for(
    "aws_macie_session",
    check_id="MACIE-001",
    service="Amazon Macie",
    severity=Severity.MEDIUM,
    category="Detection and Monitoring",
    title="Amazon Macie is not enabled in this region",
    description=(
        "Amazon Macie was explicitly observed as not enabled or paused in "
        "the assessed region. Sensitive-data discovery coverage from Macie "
        "may therefore be unavailable in that region; this is a posture signal, "
        "not proof that the organisation requires Macie everywhere."
    ),
    remediation=(
        "Review regional sensitive-data discovery requirements. Enable and "
        "configure Amazon Macie in regions where it is required, and review "
        "delegated-administrator and discovery-job coverage separately."
    ),
)
def check_macie_disabled(resource: Resource) -> list[Finding]:
    """Report Macie only when the provider explicitly observes it disabled."""
    if resource.attributes.get("enabled") is not False:
        return []
    status = resource.attributes.get("status")
    return [
        Finding.from_rule(
            check_macie_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence=f"Amazon Macie GetMacieSession status={status or 'NOT_ENABLED'}",
        )
    ]
