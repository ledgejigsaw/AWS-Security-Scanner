from aws_security_scanner.models.finding import Finding, Severity


def check_public_bucket(bucket: dict) -> list[Finding]:
    findings = []

    if bucket.get("public") is True:
        findings.append(
            Finding(
                check_id="S3-001",
                severity=Severity.CRITICAL,
                service="S3",
                resource=bucket["bucket_name"],
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
                region=bucket.get("region"),
                evidence="public=true",
            )
        )

    return findings