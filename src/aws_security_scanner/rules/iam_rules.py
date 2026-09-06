from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for("aws_iam_policy")
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
        if (
            statement.get("Effect") == "Allow"
            and statement.get("Action") == "*"
            and statement.get("Resource") == "*"
        ):
            findings.append(
                Finding(
                    check_id="IAM-001",
                    severity=Severity.CRITICAL,
                    service="IAM",
                    resource=resource.resource_id,
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
                    region=resource.region,
                    evidence="Effect=Allow, Action=*, Resource=*",
                )
            )

    return findings

@rule_for("aws_iam_policy")
def check_wildcard_permissions(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM policies containing excessively broad wildcard permissions."""

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

        resource_is_wildcard = resource_scope == "*"

        # IAM-001 already handles unrestricted Action + Resource.
        if action_is_wildcard and resource_is_wildcard:
            continue

        if action_is_wildcard or resource_is_wildcard:
            findings.append(
                Finding(
                    check_id="IAM-002",
                    severity=Severity.HIGH,
                    service="IAM",
                    resource=resource.resource_id,
                    title=(
                        "IAM policy contains excessively broad "
                        "wildcard permissions"
                    ),
                    description=(
                        "The IAM policy contains an Allow statement "
                        "using a wildcard Action or Resource. This "
                        "provides broader permissions than may be "
                        "required and can increase the impact of a "
                        "compromised identity."
                    ),
                    remediation=(
                        "Apply the principle of least privilege. "
                        "Replace wildcard Actions and Resources with "
                        "the specific permissions and resources required "
                        "by the workload or user."
                    ),
                    region=resource.region,
                    evidence=(
                        f"Effect=Allow, Action={action}, "
                        f"Resource={resource_scope}"
                    ),
                )
            )

    return findings

@rule_for("aws_iam_policy")
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
                Finding(
                    check_id="IAM-003",
                    severity=Severity.HIGH,
                    service="IAM",
                    resource=resource.resource_id,
                    title="IAM policy grants high-risk administrative permission",
                    description=(
                        f"The IAM policy grants the high-risk administrative "
                        f"permission '{matched_action}'. Such permissions "
                        "can allow an identity to modify IAM configuration, "
                        "create credentials, alter trust relationships, "
                        "or delegate permissions."
                    ),
                    remediation=(
                        "Apply the principle of least privilege. Remove "
                        "high-risk administrative permissions unless they "
                        "are explicitly required. Where required, restrict "
                        "the permission to specific resources and controlled "
                        "workflows."
                    ),
                    region=resource.region,
                    evidence=(
                        f"Effect=Allow, Action={matched_action}, "
                        f"Resource={statement.get('Resource')}"
                    ),
                )
            )

    return findings

@rule_for("aws_iam_role")
def check_insecure_trust_policy(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM roles with overly permissive trust policies."""

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

        if statement.get("Action") != "sts:AssumeRole":
            continue

        principal = statement.get("Principal")

        principal_is_wildcard = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and (
                    principal.get("AWS") == "*"
                    or principal.get("Federated") == "*"
                )
            )
        )

        if not principal_is_wildcard:
            continue

        findings.append(
            Finding(
                check_id="IAM-004",
                severity=Severity.HIGH,
                service="IAM",
                resource=resource.resource_id,
                title="IAM role has an overly permissive trust policy",
                description=(
                    "The IAM role trust policy allows sts:AssumeRole "
                    "from a wildcard principal. This can allow "
                    "unintended AWS identities to assume the role."
                ),
                remediation=(
                    "Restrict the trust policy Principal to the "
                    "specific AWS accounts, roles, services, or "
                    "federated identities that require access."
                ),
                region=resource.region,
                evidence=(
                    "Effect=Allow, Action=sts:AssumeRole, "
                    f"Principal={principal}"
                ),
            )
        )

    return findings