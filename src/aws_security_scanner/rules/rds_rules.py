from datetime import datetime, timezone, timedelta
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_db_instance",
    check_id="RDS-001",
    service="RDS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="RDS database storage encryption is disabled",
    description=(
        "The RDS database instance does not report storage encryption. "
        "Unencrypted database storage and snapshots may expose sensitive "
        "data if the underlying storage or backups are accessed improperly."
    ),
    remediation=(
        "Create an encrypted snapshot and migrate or restore the database "
        "to an encrypted instance. RDS storage encryption generally cannot "
        "be enabled in place on an existing unencrypted instance."
    ),
)
def check_rds_storage_encryption(resource: Resource) -> list[Finding]:
    """Detect RDS DB instances whose storage encryption is explicitly disabled."""
    if resource.attributes.get("storage_encrypted") is not False:
        return []

    return [
        Finding.from_rule(
            check_rds_storage_encryption,
            resource=resource.resource_id,
            region=resource.region,
            evidence="storage_encrypted=false",
        )
    ]


@rule_for(
    "aws_db_instance",
    check_id="RDS-002",
    service="RDS",
    severity=Severity.HIGH,
    category="Network Exposure",
    title="RDS database instance is publicly accessible",
    description=(
        "The RDS instance is configured as publicly accessible. Network "
        "reachability also depends on its VPC, subnet and security-group "
        "configuration, but public accessibility increases exposure."
    ),
    remediation=(
        "Disable public accessibility unless it is explicitly required. "
        "Prefer private subnets and tightly scoped security-group ingress; "
        "verify reachability rather than assuming this flag alone proves exposure."
    ),
)
def check_rds_public_accessibility(resource: Resource) -> list[Finding]:
    """Detect RDS instances configured for public accessibility."""
    if resource.attributes.get("publicly_accessible") is not True:
        return []

    return [
        Finding.from_rule(
            check_rds_public_accessibility,
            resource=resource.resource_id,
            region=resource.region,
            evidence="publicly_accessible=true",
        )
    ]


@rule_for(
    "aws_db_instance",
    check_id="RDS-003",
    service="RDS",
    severity=Severity.MEDIUM,
    category="Resilience",
    title="RDS automated backup retention is below seven days",
    description=(
        "The database instance retains automated backups for fewer than "
        "seven days. This may limit recovery options after accidental "
        "deletion, corruption or a security incident; required retention "
        "depends on the organisation's recovery and compliance policy."
    ),
    remediation=(
        "Set automated backup retention to meet the organisation's recovery "
        "point objectives and retention policy. Seven days is a baseline "
        "threshold, not a universal compliance requirement."
    ),
)
def check_rds_backup_retention(resource: Resource) -> list[Finding]:
    """Detect RDS backup retention configured below the seven-day baseline."""
    retention = resource.attributes.get("backup_retention_period")
    if not isinstance(retention, int) or isinstance(retention, bool):
        return []
    if retention >= 7:
        return []

    return [
        Finding.from_rule(
            check_rds_backup_retention,
            resource=resource.resource_id,
            region=resource.region,
            evidence=f"backup_retention_period={retention}",
        )
    ]


@rule_for(
    "aws_db_instance",
    check_id="RDS-004",
    service="RDS",
    severity=Severity.MEDIUM,
    category="Resilience",
    title="RDS deletion protection is disabled",
    description=(
        "Deletion protection is disabled for the RDS instance. This makes "
        "accidental or unauthorised deletion easier, although it does not "
        "prevent all data-loss scenarios."
    ),
    remediation=(
        "Enable deletion protection for production and other business-critical "
        "database instances, subject to the approved lifecycle process."
    ),
)
def check_rds_deletion_protection(resource: Resource) -> list[Finding]:
    """Detect RDS instances without deletion protection."""
    if resource.attributes.get("deletion_protection") is not False:
        return []

    return [
        Finding.from_rule(
            check_rds_deletion_protection,
            resource=resource.resource_id,
            region=resource.region,
            evidence="deletion_protection=false",
        )
    ]


@rule_for(
    "aws_db_instance",
    check_id="RDS-005",
    service="RDS",
    severity=Severity.MEDIUM,
    category="Transport Security",
    title="RDS server certificate is expired or nearing expiry",
    description=(
        "The RDS instance reports a server certificate that is expired or expires "
        "within the next 30 days. Certificate expiry can interrupt secure client "
        "connections if clients and server certificates are not rotated in time."
    ),
    remediation=(
        "Review the RDS certificate authority and rotation guidance for the engine, "
        "schedule any required certificate rotation, and validate client trust stores "
        "before the expiry date."
    ),
)
def check_rds_certificate_expiry(resource: Resource) -> list[Finding]:
    """Flag a reported RDS server certificate expiring within 30 days."""
    value = resource.attributes.get("certificate_valid_till")
    if isinstance(value, datetime):
        expiry = value
    elif isinstance(value, str) and value.strip():
        try:
            expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return []
    else:
        return []
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_remaining = (expiry.astimezone(timezone.utc) - now).days
    if days_remaining > 30:
        return []
    return [Finding.from_rule(
        check_rds_certificate_expiry,
        resource=resource.resource_id,
        region=resource.region,
        evidence=f"certificate_valid_till={expiry.isoformat()}; days_remaining={days_remaining}",
    )]
