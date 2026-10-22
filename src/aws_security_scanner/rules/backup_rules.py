"""Evidence-based AWS Backup protection checks."""
from datetime import datetime, timezone
from typing import Any

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


@rule_for(
    "aws_backup_protected_resource",
    check_id="BACKUP-001",
    service="AWS Backup",
    severity=Severity.MEDIUM,
    category="Resilience",
    title="No successful AWS Backup timestamp is observed",
    description="AWS Backup lists this resource as protected, but its metadata does not expose a successful backup timestamp. This is not proof that no recovery point exists; inventory may be incomplete or the service may not expose the field.",
    remediation="Review the AWS Backup job history and recovery points for this resource, confirm the intended backup plan and retention policy, and perform a restore test under an approved recovery exercise.",
)
def check_backup_timestamp_missing(resource: Resource) -> list[Finding]:
    record = resource.attributes.get("inventory_record")
    if not isinstance(record, dict):
        return []
    if record.get("LastBackupTime") is not None:
        return []
    if record.get("LastRecoveryPointArn"):
        return []
    if resource.attributes.get("discovery_complete") is False:
        return []
    return [Finding.from_rule(
        check_backup_timestamp_missing,
        resource=resource.resource_id,
        region=resource.region,
        evidence="AWS Backup protected-resource inventory contains neither LastBackupTime nor LastRecoveryPointArn; verify backup jobs and recovery points.",
    )]
