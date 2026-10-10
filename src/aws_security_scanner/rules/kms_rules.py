from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_kms_key",
    check_id="KMS-001",
    service="KMS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="Customer-managed KMS key rotation is disabled",
    description=(
        "Automatic rotation is disabled for a customer-managed symmetric "
        "encryption key. Rotation reduces the period for which a single "
        "cryptographic key material version is used."
    ),
    remediation=(
        "Enable automatic key rotation for customer-managed symmetric "
        "encryption keys where supported by the organisation's key-management "
        "policy. Review key type and rotation requirements before changing it."
    ),
)
def check_kms_key_rotation(resource: Resource) -> list[Finding]:
    """Detect customer-managed symmetric KMS keys without automatic rotation."""
    if (
        resource.attributes.get("rotation_applicable") is not True
        or resource.attributes.get("rotation_enabled") is not False
    ):
        return []

    return [
        Finding.from_rule(
            check_kms_key_rotation,
            resource=resource.resource_id,
            region=resource.region,
            evidence=(
                "key_manager=CUSTOMER, "
                "rotation_applicable=true, rotation_enabled=false"
            ),
        )
    ]


@rule_for(
    "aws_kms_key",
    check_id="KMS-002",
    service="KMS",
    severity=Severity.MEDIUM,
    category="Data Protection",
    title="KMS key is scheduled for deletion",
    description=(
        "The KMS key is pending deletion. Once deletion completes, data "
        "that depends on this key may become permanently inaccessible."
    ),
    remediation=(
        "Confirm the key is no longer required before deletion. If deletion "
        "was not intended, cancel the scheduled deletion and review key usage."
    ),
)
def check_kms_key_pending_deletion(resource: Resource) -> list[Finding]:
    """Detect KMS keys whose deletion has been scheduled."""
    if resource.attributes.get("key_state") != "PendingDeletion":
        return []

    return [
        Finding.from_rule(
            check_kms_key_pending_deletion,
            resource=resource.resource_id,
            region=resource.region,
            evidence="key_state=PendingDeletion",
        )
    ]
