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



@rule_for(
    "aws_kms_key",
    check_id="KMS-003",
    service="KMS",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="KMS key policy grants broad wildcard access",
    description=(
        "The key policy contains an Allow statement granting a wildcard "
        "principal unrestricted KMS actions without a condition. This may "
        "allow unintended identities to use or administer the key."
    ),
    remediation=(
        "Restrict the Principal to the specific AWS account, roles or users "
        "that require access. Replace wildcard KMS actions with the minimum "
        "required actions and review any intended cross-account access."
    ),
)
def check_kms_key_policy_wildcard_access(resource: Resource) -> list[Finding]:
    """Detect unconditioned wildcard-principal statements granting broad KMS actions."""
    policy = resource.attributes.get("key_policy")
    if not isinstance(policy, dict):
        return []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue

        principal = statement.get("Principal")
        wildcard_principal = (
            principal == "*"
            or (isinstance(principal, dict) and principal.get("AWS") == "*")
            or (
                isinstance(principal, dict)
                and isinstance(principal.get("AWS"), list)
                and "*" in principal.get("AWS", [])
            )
        )
        action = statement.get("Action")
        actions = [action] if isinstance(action, str) else action
        broad_actions = (
            isinstance(actions, list)
            and any(
                isinstance(item, str)
                and (item == "*" or item.lower() == "kms:*")
                for item in actions
            )
        )

        if wildcard_principal and broad_actions:
            return [
                Finding.from_rule(
                    check_kms_key_policy_wildcard_access,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "Effect=Allow, wildcard Principal, "
                        f"Action={action}, no Condition"
                    ),
                )
            ]

    return []
