from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_cloudwatch_log_group",
    check_id="CW-001",
    service="CloudWatch",
    severity=Severity.LOW,
    category="Logging and Monitoring",
    title="CloudWatch log group has no explicit retention period",
    description="The log group does not report a retentionInDays setting, so events may be retained indefinitely. Retention requirements depend on the workload and applicable policy.",
    remediation="Set a retention period aligned with incident-response, audit, privacy and cost requirements. Confirm any legal retention obligations before reducing retention.",
)
def check_cloudwatch_log_group_retention(resource: Resource) -> list[Finding]:
    if resource.attributes.get("retention_in_days") is not None:
        return []
    return [Finding.from_rule(
        check_cloudwatch_log_group_retention,
        resource=resource.resource_id,
        region=resource.region,
        evidence="retention_in_days=not_configured",
    )]


@rule_for(
    "aws_cloudwatch_metric_alarm",
    check_id="CW-002",
    service="CloudWatch",
    severity=Severity.INFO,
    category="Logging and Monitoring",
    title="CloudWatch metric alarm has no enabled alarm actions",
    description="The metric alarm does not have actions enabled or no alarm action target is configured. Some alarms are intentionally informational, so this is a review signal rather than proof of a monitoring failure.",
    remediation="Confirm the alarm's intended operational purpose and configure approved notification or response actions when required.",
)
def check_cloudwatch_alarm_actions(resource: Resource) -> list[Finding]:
    actions_enabled = resource.attributes.get("actions_enabled")
    actions = resource.attributes.get("alarm_actions")
    if actions_enabled is not True or not isinstance(actions, list) or not actions:
        return [Finding.from_rule(
            check_cloudwatch_alarm_actions,
            resource=resource.resource_id,
            region=resource.region,
            evidence=f"actions_enabled={actions_enabled!r}; alarm_actions_count={len(actions) if isinstance(actions, list) else 'unknown'}",
        )]
    return []
