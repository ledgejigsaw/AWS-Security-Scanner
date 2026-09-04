from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource


def check_public_bucket(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("public") is True:
        findings.append(
            Finding(
                check_id="S3-001",
                severity=Severity.CRITICAL,
                service="S3",
                resource=resource.resource_id,
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
                region=resource.region,
                evidence="public=true",
            )
        )

    return findings

def check_encryption(resource: Resource) -> list[Finding]:
    findings = []

    if resource.attributes.get("encryption") is False:
        findings.append(
            Finding(
                check_id="S3-002",
                severity=Severity.HIGH,
                service="S3",
                resource=resource.resource_id,
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
                region=resource.region,
                evidence="encryption=false",
            )
        )

    return findings