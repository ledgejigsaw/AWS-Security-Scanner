from aws_security_scanner.models.finding import Finding
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.rule import Severity
from aws_security_scanner.rules.decorators import rule_for
import re


@rule_for(
    "aws_s3_bucket",
    check_id="S3-001",
    service="S3",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="S3 bucket is publicly accessible",
    description=(
        "The S3 bucket is configured for public access. "
        "Publicly accessible storage can expose sensitive data "
        "to unauthorised users."
    ),
    remediation=(
        "Enable S3 Block Public Access and remove any "
        "unnecessary public bucket policies or ACLs."
    ),
)
def check_public_bucket(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("public") is True:
        findings.append(
            Finding.from_rule(
                check_public_bucket,
                resource=resource.resource_id,
                region=resource.region,
                evidence="public=true",
            )
        )

    return findings


@rule_for(
    "aws_s3_bucket",
    check_id="S3-002",
    service="S3",
    severity=Severity.HIGH,
    category="Data Protection",
    title="S3 bucket encryption is disabled",
    description=(
        "The S3 bucket does not have server-side encryption "
        "enabled. Data stored in the bucket may therefore be "
        "stored without encryption at rest."
    ),
    remediation=(
        "Enable server-side encryption for the S3 bucket. "
        "Use SSE-S3 or SSE-KMS according to the organisation's "
        "security requirements."
    ),
)
def check_encryption(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("encryption") is False:
        findings.append(
            Finding.from_rule(
                check_encryption,
                resource=resource.resource_id,
                region=resource.region,
                evidence="encryption=false",
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-003",
    service="S3",
    severity=Severity.MEDIUM,
    category="Data Protection",
    title="S3 bucket versioning is disabled",
    description=(
        "S3 bucket versioning is disabled. Without versioning, "
        "previous versions of objects cannot be retained, "
        "reducing protection against accidental deletion or "
        "overwriting of data."
    ),
    remediation=(
        "Enable S3 bucket versioning to retain previous object "
        "versions and improve data recovery capabilities."
    ),
)
def check_versioning(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("versioning") is False:
        findings.append(
            Finding.from_rule(
                check_versioning,
                resource=resource.resource_id,
                region=resource.region,
                evidence="versioning=false",
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-004",
    service="S3",
    severity=Severity.HIGH,
    category="Access Control",
    title="S3 Block Public Access is disabled",
    description=(
        "S3 Block Public Access is disabled for the bucket. "
        "This increases the risk of unintended public access "
        "through bucket policies or access control lists."
    ),
    remediation=(
        "Enable S3 Block Public Access and ensure that "
        "unnecessary public bucket policies or ACLs are removed."
    ),
)
def check_block_public_access(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("block_public_access") is False:
        findings.append(
            Finding.from_rule(
                check_block_public_access,
                resource=resource.resource_id,
                region=resource.region,
                evidence="block_public_access=false",
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-005",
    service="S3",
    severity=Severity.MEDIUM,
    category="Logging & Monitoring",
    title="S3 bucket access logging is disabled",
    description=(
        "S3 server access logging is disabled. Without access "
        "logging, requests made against the bucket may not be "
        "recorded, reducing visibility into access activity "
        "and making security investigations more difficult."
    ),
    remediation=(
        "Enable S3 server access logging and configure an "
        "appropriate target bucket for the access logs."
    ),
)
def check_logging(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("logging") is False:
        findings.append(
            Finding.from_rule(
                check_logging,
                resource=resource.resource_id,
                region=resource.region,
                evidence="logging=false",
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-006",
    service="S3",
    severity=Severity.HIGH,
    category="Access Control",
    title="S3 bucket policy allows access from any principal",
    description=(
        "The S3 bucket policy contains an Allow statement "
        "with a wildcard principal. This can permit access "
        "from any AWS principal and may expose bucket "
        "objects to unauthorised users."
    ),
    remediation=(
        "Restrict the bucket policy Principal to the "
        "specific AWS accounts, roles, or services that "
        "require access. Remove wildcard principals unless "
        "public access is explicitly required and justified."
    ),
)
def check_wildcard_bucket_policy(resource: Resource) -> list[Finding]:
    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
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
                    check_wildcard_bucket_policy,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=f"Principal={principal}",
                )
            )
            break

    return findings

check_bucket_policy = check_wildcard_bucket_policy

@rule_for(
    "aws_s3_bucket",
    check_id="S3-007",
    service="S3",
    severity=Severity.HIGH,
    category="Data Protection",
    title="S3 bucket policy does not enforce TLS",
    description=(
        "The S3 bucket policy does not explicitly deny "
        "requests made without TLS. Data could therefore "
        "be transmitted without transport encryption."
    ),
    remediation=(
        "Add an explicit Deny statement to the bucket policy "
        "that blocks requests when aws:SecureTransport is false."
    ),
)
def check_tls_enforcement(resource: Resource) -> list[Finding]:
    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        findings.append(
            Finding.from_rule(
                check_tls_enforcement,
                resource=resource.resource_id,
                region=resource.region,
                evidence="TLS enforcement not configured",
            )
        )
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    tls_enforced = False

    for statement in statements:
        if statement.get("Effect") != "Deny":
            continue

        condition = statement.get("Condition", {})

        bool_condition = condition.get("Bool", {})

        if bool_condition.get("aws:SecureTransport") == "false":
            tls_enforced = True
            break

    if not tls_enforced:
        findings.append(
            Finding.from_rule(
                check_tls_enforcement,
                resource=resource.resource_id,
                region=resource.region,
                evidence="aws:SecureTransport=false deny not found",
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-008",
    service="S3",
    severity=Severity.HIGH,
    category="Access Control",
    title="S3 bucket policy allows unrestricted S3 actions",
    description=(
        "The S3 bucket policy contains an Allow statement "
        "granting the s3:* action. This provides unrestricted "
        "S3 permissions to the specified principal."
    ),
    remediation=(
        "Replace s3:* with only the specific S3 actions "
        "required by the principal. Follow the principle "
        "of least privilege."
    ),
)
def check_excessive_s3_actions(resource: Resource) -> list[Finding]:
    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        if "s3:*" in actions:
            findings.append(
                Finding.from_rule(
                    check_excessive_s3_actions,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=f"Action={actions}",
                )
            )
            break

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-009",
    service="S3",
    severity=Severity.HIGH,
    category="Access Control",
    title="S3 bucket policy allows access to all resources",
    description=(
        "The S3 bucket policy contains an Allow statement "
        "with a wildcard resource. This can grant access "
        "beyond the intended S3 bucket resources."
    ),
    remediation=(
        "Restrict the bucket policy Resource to the specific "
        "S3 bucket or object ARNs required by the statement. "
        "Avoid using Resource='*' unless explicitly required "
        "and justified."
    ),
)
def check_wildcard_bucket_resource(resource: Resource) -> list[Finding]:
    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        resources = statement.get("Resource", [])

        if isinstance(resources, str):
            resources = [resources]

        if "*" in resources:
            findings.append(
                Finding.from_rule(
                    check_wildcard_bucket_resource,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=f"Resource={resources}",
                )
            )
            break

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-010",
    service="S3",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="S3 bucket policy allows public write access",
    description=(
        "The S3 bucket policy allows anonymous access to "
        "write operations. This can allow unauthorised users "
        "to upload, modify, or delete objects."
    ),
    remediation=(
        "Remove public write permissions from the bucket policy. "
        "Restrict write operations to specific AWS principals "
        "that require access."
    ),
)
def check_public_write_access(resource: Resource) -> list[Finding]:
    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    write_actions = {
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:PutObjectAcl",
        "s3:PutObjectTagging",
        "s3:DeleteObjectVersion",
    }

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")

        wildcard_principal = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and any(value == "*" for value in principal.values())
            )
        )

        if not wildcard_principal:
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        if "s3:*" in actions or any(
            action in write_actions for action in actions
        ):
            findings.append(
                Finding.from_rule(
                    check_public_write_access,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Principal={principal}, "
                        f"Action={actions}"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-008",
    service="S3",
    severity=Severity.HIGH,
    category="Data Protection",
    title="S3 bucket policy allows insecure transport",
    description=(
        "The S3 bucket policy does not explicitly deny "
        "requests made without secure transport."
    ),
    remediation=(
        "Add a bucket policy statement that explicitly denies "
        "S3 actions when aws:SecureTransport is false."
    ),
)
def check_insecure_transport(resource: Resource) -> list[Finding]:
    """Detect S3 bucket policies that do not enforce HTTPS."""

    findings = []

    policy = resource.attributes.get("bucket_policy")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Deny":
            continue

        condition = statement.get("Condition", {})

        bool_condition = condition.get("Bool", {})

        if bool_condition.get("aws:SecureTransport") is False:
            return findings

        if bool_condition.get("aws:SecureTransport") == "false":
            return findings

    findings.append(
        Finding.from_rule(
            check_insecure_transport,
            resource=resource.resource_id,
            region=resource.region,
            evidence="No explicit aws:SecureTransport=false deny statement",
        )
    )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-011",
    service="S3",
    severity=Severity.HIGH,
    category="Access Control",
    title="S3 bucket has a public ACL",
    description=(
        "The S3 bucket ACL grants access to the public."
    ),
    remediation=(
        "Remove public ACL grants and use S3 Block Public Access "
        "and bucket policies to control access."
    ),
)
def check_public_acl(resource: Resource) -> list[Finding]:
    """Detect S3 bucket ACL grants to the public."""

    findings = []

    # Fully enabled bucket-level Block Public Access prevents public ACL grants
    # from taking effect. Account-level settings are not discovered here.
    if resource.attributes.get("block_public_access") is True:
        return findings

    acl = resource.attributes.get("acl")

    if not acl:
        return findings

    grants = acl.get("grants", [])

    for grant in grants:
        grantee = grant.get("grantee", {})

        if grantee.get("type") != "Group":
            continue

        uri = grantee.get("uri", "")

        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
            findings.append(
                Finding.from_rule(
                    check_public_acl,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Public ACL grant: "
                        f"permission={grant.get('permission')}"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-012",
    service="S3",
    severity=Severity.MEDIUM,
    category="Access Control",
    title="S3 bucket allows ACL-based access control",
    description=(
        "The S3 bucket uses an Object Ownership setting that "
        "still permits ACL-based access control."
    ),
    remediation=(
        "Set S3 Object Ownership to BucketOwnerEnforced to "
        "disable ACL-based access control."
    ),
)
def check_acl_object_ownership(resource: Resource) -> list[Finding]:
    """Detect S3 buckets where ACL-based ownership is still enabled."""

    findings = []

    object_ownership = resource.attributes.get(
        "object_ownership"
    )

    if object_ownership is None:
        return findings

    if object_ownership != "BucketOwnerEnforced":
        findings.append(
            Finding.from_rule(
                check_acl_object_ownership,
                resource=resource.resource_id,
                region=resource.region,
                evidence=(
                    f"ObjectOwnership={object_ownership}"
                ),
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-013",
    service="S3",
    severity=Severity.INFO,
    category="Data Protection",
    title="S3 bucket MFA Delete is not enabled (review signal)",
    description=(
        "MFA Delete is not enabled for an S3 bucket with "
        "versioning enabled."
    ),
    remediation=(
        "Enable MFA Delete for the S3 bucket to provide "
        "additional protection against accidental or "
        "unauthorised deletion of object versions."
    ),
)
def check_mfa_delete(resource: Resource) -> list[Finding]:
    """Detect versioned S3 buckets without MFA Delete enabled."""

    findings = []

    versioning_configuration = resource.attributes.get(
        "versioning_configuration"
    )

    if not versioning_configuration:
        return findings

    if versioning_configuration.get("status") != "Enabled":
        return findings

    if versioning_configuration.get("mfa_delete") != "Enabled":
        findings.append(
            Finding.from_rule(
                check_mfa_delete,
                resource=resource.resource_id,
                region=resource.region,
                evidence=(
                    "Versioning enabled but MFA Delete is not enabled"
                ),
            )
        )

    return findings

@rule_for(
    "aws_s3_bucket",
    check_id="S3-014",
    service="S3",
    severity=Severity.INFO,
    category="Data Protection",
    title="Versioned S3 bucket has no noncurrent-version lifecycle expiration",
    description=(
        "The bucket has versioning enabled but no enabled lifecycle rule "
        "was observed that expires noncurrent object versions. This is a "
        "data-retention and cost review signal, not a universal security failure."
    ),
    remediation=(
        "Review retention and recovery requirements. If policy permits, add "
        "a lifecycle rule for noncurrent versions; do not shorten retention "
        "where legal, audit or recovery requirements require older versions."
    ),
)
def check_noncurrent_version_lifecycle(resource: Resource) -> list[Finding]:
    """Flag only observable versioned buckets lacking noncurrent-version expiry."""
    versioning = resource.attributes.get("versioning_configuration")
    lifecycle = resource.attributes.get("lifecycle_configuration")
    if not isinstance(versioning, dict) or versioning.get("status") != "Enabled":
        return []
    if not isinstance(lifecycle, dict):
        return []
    status = lifecycle.get("status")
    if status not in {"NOT_CONFIGURED", "CONFIGURED"}:
        return []

    rules = lifecycle.get("rules", [])
    if not isinstance(rules, list):
        return []
    has_enabled_expiration = any(
        isinstance(rule, dict)
        and rule.get("status") == "Enabled"
        and rule.get("has_noncurrent_version_expiration") is True
        for rule in rules
    )
    if has_enabled_expiration:
        return []

    evidence = (
        "No lifecycle configuration observed"
        if status == "NOT_CONFIGURED"
        else "No enabled noncurrent-version expiration rule observed"
    )
    return [
        Finding.from_rule(
            check_noncurrent_version_lifecycle,
            resource=resource.resource_id,
            region=resource.region,
            evidence=evidence,
        )
    ]


def _account_ids_from_principal(principal) -> set[str]:
    """Extract explicit 12-digit AWS account IDs from an AWS Principal value."""
    if isinstance(principal, list):
        result: set[str] = set()
        for item in principal:
            result.update(_account_ids_from_principal(item))
        return result
    if isinstance(principal, dict):
        result: set[str] = set()
        aws_principal = principal.get("AWS")
        if aws_principal is not None:
            result.update(_account_ids_from_principal(aws_principal))
        return result
    if not isinstance(principal, str) or principal == "*":
        return set()

    account_ids = set(re.findall(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):", principal))
    if re.fullmatch(r"\d{12}", principal):
        account_ids.add(principal)
    return account_ids


def _s3_policy_statement_applies_to_bucket(statement, resource: Resource) -> bool:
    """Conservatively check whether a statement resource names this bucket."""
    statement_resources = statement.get("Resource")
    if isinstance(statement_resources, str):
        statement_resources = [statement_resources]
    if not isinstance(statement_resources, list) or not statement_resources:
        return False

    bucket_name = resource.attributes.get("bucket_name") or resource.resource_id
    bucket_arn = resource.attributes.get("bucket_arn") or f"arn:aws:s3:::{bucket_name}"
    accepted = {bucket_arn, f"{bucket_arn}/*", "*"}
    return any(
        isinstance(item, str) and (item in accepted or item == bucket_name)
        for item in statement_resources
    )


@rule_for(
    "aws_s3_bucket",
    check_id="S3-015",
    service="S3",
    severity=Severity.INFO,
    category="Access Control",
    title="S3 bucket policy grants cross-account access (review signal)",
    description=(
        "An Allow statement names one or more AWS accounts other than the "
        "known bucket-owner account. Cross-account access may be intentional; "
        "this check identifies the policy grant for review and does not prove "
        "that the access is exploitable or unintended."
    ),
    remediation=(
        "Confirm that each external account and action is approved. Review "
        "conditions, organization restrictions, explicit denies, identity "
        "policies and the intended data-sharing design before changing access."
    ),
)
def check_cross_account_bucket_policy(resource: Resource) -> list[Finding]:
    """Identify explicit cross-account S3 policy grants when owner identity is known.

    This is a review signal, not a complete IAM policy evaluator. Unknown owner
    identity, malformed statements and statements with unknown resource scope
    do not produce a finding.
    """
    policy = resource.attributes.get("bucket_policy")
    if not isinstance(policy, dict):
        return []
    owner_account = resource.account_id or resource.attributes.get("bucket_owner_account")
    if not isinstance(owner_account, str) or not re.fullmatch(r"\d{12}", owner_account):
        return []

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    external_accounts: set[str] = set()
    actions_seen: set[str] = set()
    condition_present = False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not _s3_policy_statement_applies_to_bucket(statement, resource):
            continue

        actions = statement.get("Action")
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        s3_actions = {
            action for action in actions
            if isinstance(action, str)
            and (action == "*" or action.lower().startswith("s3:"))
        }
        if not s3_actions:
            continue

        principal = statement.get("Principal")
        principal_accounts = _account_ids_from_principal(principal)
        external = principal_accounts - {owner_account}
        if not external:
            continue

        external_accounts.update(external)
        actions_seen.update(s3_actions)
        condition = statement.get("Condition")
        condition_present = condition_present or (
            isinstance(condition, dict) and bool(condition)
        )

    if not external_accounts:
        return []

    finding = Finding.from_rule(
        check_cross_account_bucket_policy,
        resource=resource.resource_id,
        region=resource.region,
        evidence=(
            "external_principal_accounts="
            + ",".join(sorted(external_accounts))
            + "; actions="
            + ",".join(sorted(actions_seen))
            + f"; condition_present={str(condition_present).lower()}"
            + "; effective access not evaluated"
        ),
    )
    finding.account_id = owner_account
    return [finding]



@rule_for(
    "aws_s3_bucket",
    check_id="S3-016",
    service="S3",
    severity=Severity.INFO,
    category="Data Protection",
    title="Versioned S3 bucket has no Object Lock configuration (review signal)",
    description=(
        "The bucket has versioning enabled but Object Lock is explicitly not "
        "configured. Object Lock can support immutable retention requirements, "
        "but its absence is not a universal security failure."
    ),
    remediation=(
        "Review data classification, regulatory obligations and recovery "
        "requirements. If immutable retention is required, evaluate S3 Object "
        "Lock and an appropriate default retention policy before enabling it."
    ),
)
def check_object_lock_review(resource: Resource) -> list[Finding]:
    """Signal an absent Object Lock configuration only when state is known."""
    versioning = resource.attributes.get("versioning_configuration")
    object_lock = resource.attributes.get("object_lock_configuration")

    if not isinstance(versioning, dict) or versioning.get("status") != "Enabled":
        return []
    if not isinstance(object_lock, dict):
        return []
    if object_lock.get("status") != "NOT_CONFIGURED":
        return []

    return [
        Finding.from_rule(
            check_object_lock_review,
            resource=resource.resource_id,
            region=resource.region,
            evidence=(
                "versioning=Enabled; object_lock=NOT_CONFIGURED; "
                "policy requirement not evaluated"
            ),
        )
    ]
\n\n@rule_for(
    "aws_s3_account_public_access_block",
    check_id="S3-017",
    service="S3",
    severity=Severity.MEDIUM,
    category="Preventive Controls",
    title="S3 account-level Block Public Access is not fully enabled",
    description=(
        "The account-level S3 Block Public Access configuration is absent or "
        "does not explicitly enable all four protections. Bucket-level controls "
        "may still provide protection, so this is an account-wide posture signal "
        "and not a complete effective-access evaluation."
    ),
    remediation=(
        "Review account and organisation requirements, then enable the missing "
        "account-level S3 Block Public Access settings where appropriate. "
        "Validate bucket-level settings and policy exceptions separately."
    ),
)
def check_s3_account_block_public_access(resource: Resource) -> list[Finding]:
    """Report absent or explicitly incomplete account-level S3 BPA settings."""
    configured = resource.attributes.get("configured")
    settings = {
        "block_public_acls": resource.attributes.get("block_public_acls"),
        "ignore_public_acls": resource.attributes.get("ignore_public_acls"),
        "block_public_policy": resource.attributes.get("block_public_policy"),
        "restrict_public_buckets": resource.attributes.get("restrict_public_buckets"),
    }
    if configured is False:
        evidence = "account-level public access block configuration=NOT_CONFIGURED"
    elif configured is True:
        disabled = sorted(name for name, value in settings.items() if value is False)
        if not disabled:
            return []
        evidence = "account-level Block Public Access settings not enabled: " + ", ".join(disabled)
    else:
        return []

    return [
        Finding.from_rule(
            check_s3_account_block_public_access,
            resource=resource.resource_id,
            region=resource.region,
            evidence=evidence,
        )
    ]


