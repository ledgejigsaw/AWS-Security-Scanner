from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-001",
    service="CloudTrail",
    severity=Severity.HIGH,
    category="Logging & Monitoring",
    title="CloudTrail trail is not logging",
    description=(
        "The CloudTrail trail is not currently logging events. "
        "Without active trail logging, account activity may not be "
        "recorded for investigation, detection or audit."
    ),
    remediation=(
        "Start logging for the trail and confirm that it is delivering "
        "events to its configured destination."
    ),
)
def check_cloudtrail_logging(resource: Resource) -> list[Finding]:
    """Detect CloudTrail trails that are not actively logging."""
    if resource.attributes.get("is_logging") is not False:
        return []

    return [
        Finding.from_rule(
            check_cloudtrail_logging,
            resource=resource.resource_id,
            region=resource.region,
            evidence="is_logging=false",
        )
    ]


@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-002",
    service="CloudTrail",
    severity=Severity.MEDIUM,
    category="Logging & Monitoring",
    title="CloudTrail trail is not multi-region",
    description=(
        "The trail is not configured as a multi-region trail. "
        "Activity in other enabled regions may not be captured by this trail."
    ),
    remediation=(
        "Configure at least one active CloudTrail trail as a multi-region "
        "trail and verify coverage of enabled AWS regions."
    ),
)
def check_cloudtrail_multi_region(resource: Resource) -> list[Finding]:
    """Detect CloudTrail trails that do not cover multiple regions."""
    if resource.attributes.get("is_multi_region_trail") is not False:
        return []

    return [
        Finding.from_rule(
            check_cloudtrail_multi_region,
            resource=resource.resource_id,
            region=resource.region,
            evidence="is_multi_region_trail=false",
        )
    ]



@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-003",
    service="CloudTrail",
    severity=Severity.MEDIUM,
    category="Logging & Monitoring",
    title="CloudTrail log-file validation is disabled",
    description=(
        "Log-file validation helps detect modification or deletion of "
        "CloudTrail log files after delivery. It does not prevent changes, "
        "but supports integrity verification."
    ),
    remediation=(
        "Enable log-file validation for the trail and ensure the operational "
        "process periodically validates delivered digest files."
    ),
)
def check_cloudtrail_log_file_validation(resource: Resource) -> list[Finding]:
    """Detect trails that do not have log-file validation enabled."""
    if resource.attributes.get("log_file_validation_enabled") is not False:
        return []

    return [
        Finding.from_rule(
            check_cloudtrail_log_file_validation,
            resource=resource.resource_id,
            region=resource.region,
            evidence="log_file_validation_enabled=false",
        )
    ]



@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-004",
    service="CloudTrail",
    severity=Severity.INFO,
    category="Logging & Monitoring",
    title="CloudTrail trail has no CloudWatch Logs integration",
    description="No CloudWatch Logs log-group integration was observed for this trail. This is a monitoring integration review signal, not proof that trail events are not being delivered to S3.",
    remediation="Review whether near-real-time alerting requires CloudWatch Logs integration. If needed, configure a protected log group and an appropriately scoped delivery role.",
)
def check_cloudtrail_cloudwatch_logs_integration(resource: Resource) -> list[Finding]:
    if "cloudwatch_logs_log_group_arn" not in resource.attributes:
        return []
    if resource.attributes.get("cloudwatch_logs_log_group_arn"):
        return []
    return [Finding.from_rule(
        check_cloudtrail_cloudwatch_logs_integration,
        resource=resource.resource_id,
        region=resource.region,
        evidence="CloudWatchLogsLogGroupArn is absent from discovered trail metadata",
    )]


@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-005",
    service="CloudTrail",
    severity=Severity.MEDIUM,
    category="Logging & Monitoring",
    title="CloudTrail reports a recent delivery error",
    description="CloudTrail reports a delivery error in its trail status. Log delivery should be investigated because recent activity may not have reached the configured destination.",
    remediation="Investigate the reported delivery error, validate destination permissions and KMS/S3 configuration, and confirm successful delivery resumes.",
)
def check_cloudtrail_delivery_error(resource: Resource) -> list[Finding]:
    error = resource.attributes.get("latest_delivery_error")
    if not isinstance(error, str) or not error.strip():
        return []
    return [Finding.from_rule(
        check_cloudtrail_delivery_error,
        resource=resource.resource_id,
        region=resource.region,
        evidence=f"LatestDeliveryError={error.strip()[:240]}",
    )]


@rule_for(
    "aws_cloudtrail_trail", check_id="CT-006", service="CloudTrail",
    severity=Severity.MEDIUM, category="Logging & Monitoring",
    title="CloudTrail management event selectors are not observed",
    description="Accessible selector metadata does not show management events enabled. This check does not infer data-event coverage from management-event configuration.",
    remediation="Review basic and advanced event selectors. Enable appropriate management-event logging and validate required coverage for the organisation.",
)
def check_cloudtrail_management_event_coverage(resource: Resource) -> list[Finding]:
    if resource.attributes.get("event_selector_discovery") != "success":
        return []
    if resource.attributes.get("management_events_logged") is not False:
        return []
    return [Finding.from_rule(
        check_cloudtrail_management_event_coverage,
        resource=resource.resource_id, region=resource.region,
        evidence="event_selector_discovery=success; no selector explicitly enables management events",
    )]

@rule_for(
    "aws_cloudtrail_trail",
    check_id="CT-007",
    service="CloudTrail",
    severity=Severity.INFO,
    category="Logging & Monitoring",
    title="CloudTrail trail is account-scoped rather than organisation-scoped",
    description=(
        "The trail metadata explicitly identifies this as an account-level "
        "trail. Account-level trails can be appropriate, but organisations "
        "should review whether central organisation-wide logging is required. "
        "This finding does not prove that no other organisation trail exists."
    ),
    remediation=(
        "Review the organisation's central logging design and verify that an "
        "appropriately managed organisation trail covers the required accounts "
        "and regions. Retain account-level trails where they serve a documented purpose."
    ),
)
def check_cloudtrail_organization_trail_review(resource: Resource) -> list[Finding]:
    """Emit an informational review signal for explicitly account-scoped trails."""
    if resource.attributes.get("is_organization_trail") is not False:
        return []
    return [Finding.from_rule(
        check_cloudtrail_organization_trail_review,
        resource=resource.resource_id,
        region=resource.region,
        evidence="is_organization_trail=false; organization_trail_scope=account",
    )]
