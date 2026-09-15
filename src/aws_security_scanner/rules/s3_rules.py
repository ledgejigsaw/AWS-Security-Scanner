from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for

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