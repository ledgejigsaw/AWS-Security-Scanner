from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for
from datetime import datetime, timezone



# IAM-001 — Unrestricted IAM Permissions

@rule_for(
    "aws_iam_policy",
    check_id="IAM-001",
    service="IAM",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="IAM policy grants unrestricted permissions",
    description=(
        "The IAM policy contains an Allow statement "
        "granting all actions against all resources. "
        "This provides unrestricted permissions and "
        "creates a significant privilege escalation "
        "and compromise risk."
    ),
    remediation=(
        "Apply the principle of least privilege. "
        "Restrict the allowed actions to only those "
        "required and limit Resource to the specific "
        "AWS resources that require access."
    ),
)


def check_overly_permissive_policy(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM policies granting unrestricted permissions."""

    findings = []

    policy = resource.attributes.get("policy_document")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")
        resource_scope = statement.get("Resource")

        action_is_wildcard = (
            action == "*"
            or (
                isinstance(action, list)
                and "*" in action
            )
        )

        resource_is_wildcard = (
            resource_scope == "*"
            or (
                isinstance(resource_scope, list)
                and "*" in resource_scope
            )
        )

        if action_is_wildcard and resource_is_wildcard:

            findings.append(
                Finding.from_rule(
                    check_overly_permissive_policy,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "Effect=Allow, "
                        f"Action={action}, "
                        f"Resource={resource_scope}"
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# IAM-002 — Wildcard IAM Permissions
# ---------------------------------------------------------------------------

@rule_for(
    "aws_iam_policy",
    check_id="IAM-002",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM policy contains excessively broad wildcard permissions",
    description=(
        "The IAM policy contains an Allow statement "
        "using a wildcard Action, NotAction, or Resource. "
        "This provides broader permissions than may be "
        "required and can increase the impact of a "
        "compromised identity."
    ),
    remediation=(
        "Apply the principle of least privilege. "
        "Replace wildcard Actions, NotActions, and Resources "
        "with the specific permissions and resources required "
        "by the workload or user."
    ),
)
def check_wildcard_permissions(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM policies containing excessively broad permissions."""

    findings = []

    policy = resource.attributes.get("policy_document")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")
        not_action = statement.get("NotAction")
        resource_scope = statement.get("Resource")

        action_is_wildcard = (
            action == "*"
            or (
                isinstance(action, str)
                and "*" in action
            )
            or (
                isinstance(action, list)
                and any(
                    isinstance(item, str)
                    and "*" in item
                    for item in action
                )
            )
        )

        not_action_is_broad = (
            isinstance(not_action, str)
            or (
                isinstance(not_action, list)
                and len(not_action) > 0
            )
        )

        resource_is_wildcard = (
            resource_scope == "*"
            or (
                isinstance(resource_scope, list)
                and "*" in resource_scope
            )
        )

        # IAM-001 already handles unrestricted
        # Action + Resource permissions.
        if action_is_wildcard and resource_is_wildcard:
            continue

        if (
            action_is_wildcard
            or not_action_is_broad
            or resource_is_wildcard
        ):

            findings.append(
                Finding.from_rule(
                    check_wildcard_permissions,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Effect=Allow, "
                        f"Action={action}, "
                        f"NotAction={not_action}, "
                        f"Resource={resource_scope}"
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# IAM-003 — High-Risk Administrative Permissions
# ---------------------------------------------------------------------------

@rule_for(
    "aws_iam_policy",
    check_id="IAM-003",
    service="IAM",
    severity=Severity.HIGH,
    category="Privilege Management",
    title="IAM policy grants high-risk administrative permission",
    description=(
        "The IAM policy grants a high-risk administrative "
        "permission. Such permissions can allow an identity "
        "to modify IAM configuration, create credentials, "
        "alter trust relationships, or delegate permissions."
    ),
    remediation=(
        "Apply the principle of least privilege. Remove "
        "high-risk administrative permissions unless they "
        "are explicitly required. Where required, restrict "
        "the permission to specific resources and controlled "
        "workflows."
    ),
)
def check_excessive_administrative_permissions(
    resource: Resource,
) -> list[Finding]:
    """Detect high-risk IAM administrative permissions."""

    findings = []

    policy = resource.attributes.get("policy_document")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    high_risk_actions = {
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
    }

    for statement in statements:

        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")

        if isinstance(action, str):
            actions = [action]
        elif isinstance(action, list):
            actions = action
        else:
            continue

        matched_actions = high_risk_actions.intersection(actions)

        for matched_action in matched_actions:

            findings.append(
                Finding.from_rule(
                    check_excessive_administrative_permissions,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Effect=Allow, "
                        f"Action={matched_action}, "
                        f"Resource={statement.get('Resource')}"
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# IAM-004 — Insecure IAM Role Trust Policy
# ---------------------------------------------------------------------------

@rule_for(
    "aws_iam_role",
    check_id="IAM-004",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM role trust policy allows wildcard principal",
    description=(
        "The IAM role trust policy contains an Allow statement "
        "with a wildcard principal. This can allow unintended "
        "AWS principals to assume the role."
    ),
    remediation=(
        "Restrict the role trust policy Principal to the "
        "specific AWS accounts, roles, or services that "
        "require access. Avoid wildcard principals unless "
        "the trust relationship is explicitly required "
        "and justified."
    ),
)

def check_insecure_trust_policy(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM role trust policies with wildcard principals."""

    findings = []

    policy = resource.attributes.get(
        "assume_role_policy_document"
    )

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    supported_actions = {
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
    }

    for statement in statements:

        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")

        if isinstance(action, str):
            actions = [action]
        elif isinstance(action, list):
            actions = action
        else:
            continue

        if not any(
            trust_action in supported_actions
            for trust_action in actions
        ):
            continue

        principal = statement.get("Principal")

        wildcard_principal = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and any(
                    value == "*"
                    for value in principal.values()
                )
            )
        )

        if wildcard_principal:
            findings.append(
                Finding.from_rule(
                    check_insecure_trust_policy,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Principal={principal}, "
                        f"Action={action}"
                    ),
                )
            )

            break

    return findings

@rule_for(
    "aws_iam_user",
    check_id="IAM-005",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM user does not have MFA enabled",
    description=(
        "The IAM user does not have multi-factor authentication "
        "enabled."
    ),
    remediation=(
        "Enable MFA for IAM users, particularly users with "
        "console access."
    ),
)
def check_user_without_mfa(resource: Resource) -> list[Finding]:
    """Detect IAM users without MFA enabled."""

    findings = []

    mfa_enabled = resource.attributes.get("mfa_enabled")

    if mfa_enabled is False:
        findings.append(
            Finding.from_rule(
                check_user_without_mfa,
                resource=resource.resource_id,
                region=resource.region,
                evidence="MFA is not enabled",
            )
        )

    return findings

@rule_for(
    "aws_iam_user",
    check_id="IAM-006",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM user has an active access key",
    description=(
        "The IAM user has an active programmatic access key."
    ),
    remediation=(
        "Remove unused access keys and use short-lived "
        "credentials such as IAM roles where possible."
    ),
)

def check_active_access_key(resource: Resource) -> list[Finding]:
    """Detect IAM users with active access keys."""

    findings = []

    access_keys = resource.attributes.get("access_keys", [])

    for access_key in access_keys:
        if access_key.get("status") == "Active":
            findings.append(
                Finding.from_rule(
                    check_active_access_key,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Active access key: "
                        f"{access_key.get('access_key_id')}"
                    ),
                )
            )
            break

    return findings

from datetime import datetime, timezone

@rule_for(
    "aws_iam_user",
    check_id="IAM-007",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM access key is older than 90 days",
    description=(
        "The IAM user has an active access key that is "
        "older than 90 days."
    ),
    remediation=(
        "Rotate old access keys regularly and remove "
        "unused credentials."
    ),
)
def check_old_access_key(resource: Resource) -> list[Finding]:
    """Detect active IAM access keys older than 90 days."""

    findings = []

    access_keys = resource.attributes.get("access_keys", [])

    now = datetime.now(timezone.utc)

    for access_key in access_keys:
        if access_key.get("status") != "Active":
            continue

        created_at = access_key.get("created_at")

        if not created_at:
            continue

        created_date = datetime.fromisoformat(
            created_at.replace("Z", "+00:00")
)

        if created_date.tzinfo is None:
            created_date = created_date.replace(tzinfo=timezone.utc)

        age_days = (now - created_date).days

        if age_days > 90:
            findings.append(
                Finding.from_rule(
                    check_old_access_key,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Access key: "
                        f"{access_key.get('access_key_id')}, "
                        f"age: {age_days} days"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_iam_user",
    check_id="IAM-008",
    service="IAM",
    severity=Severity.MEDIUM,
    category="Access Control",
    title="IAM user has a stale password",
    description=(
        "The IAM user has a password that has not been used "
        "for more than 90 days."
    ),
    remediation=(
        "Remove unused passwords or disable console access "
        "for users that no longer require it."
    ),
)
def check_stale_password_user(resource: Resource) -> list[Finding]:
    """Detect IAM users with passwords unused for more than 90 days."""

    findings = []

    password_enabled = resource.attributes.get(
        "password_enabled",
        False,
    )

    if not password_enabled:
        return findings

    password_last_used = resource.attributes.get(
        "password_last_used"
    )

    if not password_last_used:
        return findings

    now = datetime.now(timezone.utc)

    last_used = datetime.fromisoformat(
        password_last_used.replace("Z", "+00:00")
    )

    if last_used.tzinfo is None:
        last_used = last_used.replace(tzinfo=timezone.utc)

    age_days = (now - last_used).days

    if age_days > 90:
        findings.append(
            Finding.from_rule(
                check_stale_password_user,
                resource=resource.resource_id,
                region=resource.region,
                evidence=(
                    f"Password last used: "
                    f"{password_last_used}, "
                    f"age: {age_days} days"
                ),
            )
        )

    return findings

@rule_for(
    "aws_iam_user",
    check_id="IAM-009",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM inline policy contains wildcard permissions",
    description=(
        "The IAM user has an inline policy that grants "
        "wildcard permissions."
    ),
    remediation=(
        "Replace wildcard permissions with the minimum "
        "actions and resources required."
    ),
)
def check_inline_wildcard_permissions(
    resource: Resource,
) -> list[Finding]:
    """Detect wildcard permissions in IAM user inline policies."""

    findings = []

    inline_policies = resource.attributes.get(
        "inline_policies",
        [],
    )

    for policy in inline_policies:
        policy_document = policy.get("policy_document", {})
        statements = policy_document.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            action = statement.get("Action")
            resource_value = statement.get("Resource")

            wildcard_action = (
                action == "*"
                or isinstance(action, list)
                and "*" in action
            )

            wildcard_resource = (
                resource_value == "*"
                or isinstance(resource_value, list)
                and "*" in resource_value
            )

            if wildcard_action and wildcard_resource:
                findings.append(
                    Finding.from_rule(
                        check_inline_wildcard_permissions,
                        resource=resource.resource_id,
                        region=resource.region,
                        evidence=(
                            f"Action={action}, "
                            f"Resource={resource_value}"
                        ),
                    )
                )
                return findings

    return findings

@rule_for(
    "aws_iam_policy",
    check_id="IAM-010",
    service="IAM",
    severity=Severity.HIGH,
    category="Privilege Escalation",
    title="IAM policy allows privilege escalation",
    description=(
        "The IAM policy contains permissions that can be "
        "used to escalate privileges."
    ),
    remediation=(
        "Restrict privilege-management permissions to the "
        "specific resources and actions required."
    ),
)
def check_privilege_escalation_permissions(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM permissions commonly associated with privilege escalation."""

    findings = []

    policy = resource.attributes.get("policy_document", {})
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    escalation_actions = {
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
        "iam:PassRole",
    }

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        matched_actions = [
            action
            for action in actions
            if action in escalation_actions
        ]

        if matched_actions:
            findings.append(
                Finding.from_rule(
                    check_privilege_escalation_permissions,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Privilege escalation actions: "
                        f"{matched_actions}"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_iam_policy",
    check_id="IAM-011",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="Sensitive IAM action allowed on all resources",
    description=(
        "The IAM policy allows a sensitive IAM action "
        "against all resources."
    ),
    remediation=(
        "Restrict sensitive IAM actions to specific resources "
        "wherever possible."
    ),
)
def check_sensitive_iam_action(
    resource: Resource,
) -> list[Finding]:
    """Detect sensitive IAM actions against wildcard resources."""

    findings = []

    policy = resource.attributes.get("policy_document", {})
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    sensitive_actions = {
        "iam:CreateUser",
        "iam:CreateRole",
        "iam:CreatePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
    }

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        resource_value = statement.get("Resource")

        if resource_value != "*":
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        matched_actions = [
            action
            for action in actions
            if action in sensitive_actions
        ]

        if matched_actions:
            findings.append(
                Finding.from_rule(
                    check_sensitive_iam_action,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Actions={matched_actions}, "
                        "Resource=*"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_iam_role",
    check_id="IAM-012",
    service="IAM",
    severity=Severity.HIGH,
    category="Access Control",
    title="IAM role has a broad trust relationship",
    description=(
        "The IAM role trust policy allows another AWS "
        "account to assume the role through a broad "
        "root principal."
    ),
    remediation=(
        "Restrict the trust relationship to the specific "
        "AWS account, role, or principal that requires access."
    ),
)
def check_broad_trust_relationship(
    resource: Resource,
) -> list[Finding]:
    """Detect broad AWS account trust relationships."""

    findings = []

    policy = resource.attributes.get(
        "assume_role_policy_document"
    )

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        action = statement.get("Action")

        if isinstance(action, str):
            actions = [action]
        elif isinstance(action, list):
            actions = action
        else:
            continue

        if "sts:AssumeRole" not in actions:
            continue

        principal = statement.get("Principal", {})

        if not isinstance(principal, dict):
            continue

        aws_principal = principal.get("AWS")

        if isinstance(aws_principal, str):
            aws_principals = [aws_principal]
        elif isinstance(aws_principal, list):
            aws_principals = aws_principal
        else:
            continue

        broad_principals = [
            value
            for value in aws_principals
            if value.endswith(":root")
        ]

        if broad_principals:
            findings.append(
                Finding.from_rule(
                    check_broad_trust_relationship,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"AWS principals: "
                        f"{broad_principals}"
                    ),
                )
            )
            break

    return findings


# IAM-013 — Root account MFA disabled
@rule_for("aws_iam_account", check_id="IAM-013", service="IAM",
    severity=Severity.CRITICAL, category="Access Control",
    title="AWS root account does not have MFA enabled",
    description="The credential report indicates that MFA is not enabled for the AWS root account.",
    remediation="Enable MFA on the root account and secure the root credentials.")
def check_root_account_without_mfa(resource: Resource) -> list[Finding]:
    """Detect an AWS root account without MFA."""
    if resource.attributes.get("root_mfa_enabled") is not False:
        return []
    return [Finding.from_rule(check_root_account_without_mfa,
        resource=resource.resource_id, region=resource.region,
        evidence="Credential report: mfa_active=false")]


# IAM-014 — Root account access keys present
@rule_for("aws_iam_account", check_id="IAM-014", service="IAM",
    severity=Severity.CRITICAL, category="Credential Management",
    title="AWS root account has an active access key",
    description="The AWS root account has an active programmatic access key, increasing the impact of credential compromise.",
    remediation="Delete root-account access keys. Use an appropriately scoped IAM role or identity for programmatic access.")
def check_root_account_access_keys(resource: Resource) -> list[Finding]:
    """Detect active access keys on the AWS root account."""
    active = [name for name in ("root_access_key_1_active", "root_access_key_2_active")
              if resource.attributes.get(name) is True]
    if not active:
        return []
    return [Finding.from_rule(check_root_account_access_keys,
        resource=resource.resource_id, region=resource.region,
        evidence=f"Active root access-key fields: {active}")]


# IAM-015 — Active access key unused for more than 90 days
@rule_for("aws_iam_user", check_id="IAM-015", service="IAM",
    severity=Severity.MEDIUM, category="Credential Management",
    title="IAM access key has not been used in more than 90 days",
    description="An active IAM access key has never been used or has not been used for more than 90 days.",
    remediation="Confirm whether the key is still required. Deactivate or delete unused keys and rotate keys that remain necessary.")
def check_unused_access_key(resource: Resource) -> list[Finding]:
    """Detect active access keys with no use in the last 90 days."""
    now = datetime.now(timezone.utc)
    for key in resource.attributes.get("access_keys", []):
        if key.get("status") != "Active" or not key.get("created_at"):
            continue
        try:
            created = datetime.fromisoformat(key["created_at"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        last_used_at = key.get("last_used_date")
        if last_used_at in (None, "", "N/A", "no_information", "not_supported"):
            age_days = (now - created).days
        else:
            try:
                last_used = datetime.fromisoformat(last_used_at.replace("Z", "+00:00"))
            except (TypeError, ValueError):
                continue
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            age_days = (now - last_used).days
        if age_days > 90:
            return [Finding.from_rule(check_unused_access_key,
                resource=resource.resource_id, region=resource.region,
                evidence=f"Access key {key.get('access_key_id')} has no use in {age_days} days or has never been used")]
    return []


# IAM-016 — Never-used console password
@rule_for("aws_iam_user", check_id="IAM-016", service="IAM",
    severity=Severity.MEDIUM, category="Credential Management",
    title="IAM console password has never been used",
    description="An IAM user has an enabled console password that has never been used, and the password has existed for more than 90 days.",
    remediation="Confirm whether console access is required. Remove unnecessary passwords or disable console access for unused accounts.")
def check_never_used_console_password(resource: Resource) -> list[Finding]:
    """Detect long-lived console passwords that have never been used."""
    if resource.attributes.get("password_enabled") is not True:
        return []
    last_used = resource.attributes.get("password_last_used")
    if last_used not in (None, "", "N/A", "no_information", "not_supported"):
        return []
    changed_at = resource.attributes.get("password_last_changed")
    if not changed_at or changed_at in ("N/A", "no_information", "not_supported"):
        return []
    try:
        changed = datetime.fromisoformat(changed_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return []
    if changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - changed).days
    if age_days <= 90:
        return []
    return [Finding.from_rule(check_never_used_console_password,
        resource=resource.resource_id, region=resource.region,
        evidence=f"Password has never been used; last changed {age_days} days ago")]


# IAM-017 — IAM role unused for more than 90 days
@rule_for("aws_iam_role", check_id="IAM-017", service="IAM",
    severity=Severity.LOW, category="Credential Management",
    title="IAM role has not been used in more than 90 days",
    description="The role has no recorded use within the last 90 days, or has never been used despite being older than 90 days. Review it for removal or tighter trust and permission policies.",
    remediation="Verify dependencies and ownership before removing the role. If it is still required, document its purpose and review its trust and permission policies.")
def check_unused_iam_role(resource: Resource) -> list[Finding]:
    """Identify potentially stale IAM roles for review."""
    now = datetime.now(timezone.utc)
    last_used_at = resource.attributes.get("last_used_date")
    reference_date = last_used_at or resource.attributes.get("create_date")
    if not reference_date:
        return []
    try:
        reference = datetime.fromisoformat(reference_date.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return []
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    age_days = (now - reference).days
    if age_days <= 90:
        return []
    return [Finding.from_rule(check_unused_iam_role,
        resource=resource.resource_id, region=resource.region,
        evidence=(f"Last used {age_days} days ago" if last_used_at
                  else f"No recorded use; role created {age_days} days ago"))]
