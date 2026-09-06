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
