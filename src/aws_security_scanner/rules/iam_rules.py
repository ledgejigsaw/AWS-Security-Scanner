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