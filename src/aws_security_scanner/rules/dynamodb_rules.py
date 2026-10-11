from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_dynamodb_table",
    check_id="DDB-001",
    service="DynamoDB",
    severity=Severity.MEDIUM,
    category="Resilience",
    title="DynamoDB point-in-time recovery is disabled",
    description=(
        "The table's continuous-backup metadata explicitly reports point-in-time "
        "recovery as disabled. Without PITR, recovery from accidental writes or "
        "deletes may be limited to available backups."
    ),
    remediation=(
        "Enable point-in-time recovery for tables whose recovery requirements "
        "justify it, and verify retention and recovery procedures."
    ),
)
def check_dynamodb_pitr_disabled(resource: Resource) -> list[Finding]:
    """Flag only an explicit DISABLED point-in-time recovery state."""
    if resource.attributes.get("point_in_time_recovery_status") != "DISABLED":
        return []
    return [
        Finding.from_rule(
            check_dynamodb_pitr_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="point_in_time_recovery_status=DISABLED",
        )
    ]


@rule_for(
    "aws_dynamodb_table",
    check_id="DDB-002",
    service="DynamoDB",
    severity=Severity.HIGH,
    category="Data Protection",
    title="DynamoDB table reports server-side encryption disabled",
    description=(
        "The table metadata explicitly reports server-side encryption as disabled. "
        "The rule does not infer encryption state from missing metadata."
    ),
    remediation=(
        "Investigate the reported table encryption state and ensure data-at-rest "
        "encryption meets the applicable AWS and organisational requirements."
    ),
)
def check_dynamodb_sse_disabled(resource: Resource) -> list[Finding]:
    """Flag only an explicit DISABLED SSE status from the API."""
    if resource.attributes.get("sse_status") != "DISABLED":
        return []
    return [
        Finding.from_rule(
            check_dynamodb_sse_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="sse_status=DISABLED",
        )
    ]


@rule_for(
    "aws_dynamodb_table",
    check_id="DDB-003",
    service="DynamoDB",
    severity=Severity.MEDIUM,
    category="Resilience",
    title="DynamoDB table deletion protection is disabled",
    description=(
        "The table metadata explicitly reports deletion protection as disabled. "
        "Deletion protection reduces the risk of accidental table deletion but "
        "does not replace backups or access controls."
    ),
    remediation=(
        "Enable deletion protection for tables where accidental deletion would "
        "cause unacceptable impact, and retain independent backup and recovery controls."
    ),
)
def check_dynamodb_deletion_protection_disabled(resource: Resource) -> list[Finding]:
    """Flag only explicit false; unknown deletion-protection state is not a finding."""
    if resource.attributes.get("deletion_protection_enabled") is not False:
        return []
    return [
        Finding.from_rule(
            check_dynamodb_deletion_protection_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="deletion_protection_enabled=false",
        )
    ]
