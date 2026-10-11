from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_ecr_repository",
    check_id="ECR-001",
    service="ECR",
    severity=Severity.HIGH,
    category="Supply Chain Security",
    title="ECR repository permits mutable image tags",
    description=(
        "The repository is explicitly configured with mutable image tags. "
        "A tag can be moved to a different image after review or deployment, "
        "which can weaken image provenance and reproducibility. Some workflows "
        "intentionally use mutable tags, so this is a configurable baseline."
    ),
    remediation=(
        "Prefer immutable image tags for release artifacts, and deploy images "
        "by digest where practical. If mutable tags are required, document the "
        "workflow and enforce equivalent provenance and promotion controls."
    ),
)
def check_ecr_mutable_image_tags(resource: Resource) -> list[Finding]:
    """Flag ECR repositories explicitly configured for mutable image tags."""
    if resource.attributes.get("image_tag_mutability") != "MUTABLE":
        return []

    return [
        Finding.from_rule(
            check_ecr_mutable_image_tags,
            resource=resource.resource_id,
            region=resource.region,
            evidence="image_tag_mutability=MUTABLE",
        )
    ]


@rule_for(
    "aws_ecr_repository",
    check_id="ECR-002",
    service="ECR",
    severity=Severity.MEDIUM,
    category="Vulnerability Management",
    title="ECR image scanning on push is disabled",
    description=(
        "The repository's image-scanning configuration explicitly disables "
        "scan-on-push. This can delay discovery of known vulnerabilities in "
        "container images; scanning configuration and coverage depend on the "
        "registry's configured scanning mode."
    ),
    remediation=(
        "Enable scan-on-push where supported and appropriate, and confirm that "
        "the registry's scanning configuration covers the images and severity "
        "levels required by your deployment process."
    ),
)
def check_ecr_scan_on_push_disabled(resource: Resource) -> list[Finding]:
    """Flag ECR repositories whose scan-on-push setting is explicitly false."""
    if resource.attributes.get("scan_on_push") is not False:
        return []

    return [
        Finding.from_rule(
            check_ecr_scan_on_push_disabled,
            resource=resource.resource_id,
            region=resource.region,
            evidence="scan_on_push=false",
        )
    ]
