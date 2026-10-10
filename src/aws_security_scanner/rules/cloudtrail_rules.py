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
