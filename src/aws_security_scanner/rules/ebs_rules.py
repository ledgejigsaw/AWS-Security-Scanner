from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_ebs_volume",
    check_id="EBS-001",
    service="EBS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="EBS volume is explicitly unencrypted",
    description="The EBS volume is explicitly reported as unencrypted, so data at rest is not protected by EBS encryption.",
    remediation="Enable EBS encryption for new volumes and migrate or snapshot/restore existing unencrypted volumes using an approved encrypted workflow.",
)
def check_ebs_volume_encryption(resource: Resource) -> list[Finding]:
    if resource.attributes.get("encrypted") is not False:
        return []
    return [Finding.from_rule(
        check_ebs_volume_encryption,
        resource=resource.resource_id,
        region=resource.region,
        evidence="Encrypted=false",
    )]


@rule_for(
    "aws_ebs_snapshot",
    check_id="EBS-002",
    service="EBS",
    severity=Severity.HIGH,
    category="Data Protection",
    title="EBS snapshot is explicitly unencrypted",
    description="The snapshot is explicitly reported as unencrypted. Snapshot data may contain recoverable copies of sensitive volume data.",
    remediation="Create an encrypted copy using an approved KMS key, verify dependent recovery workflows, and review the source volume's encryption requirements.",
)
def check_ebs_snapshot_encryption(resource: Resource) -> list[Finding]:
    if resource.attributes.get("encrypted") is not False:
        return []
    return [Finding.from_rule(
        check_ebs_snapshot_encryption,
        resource=resource.resource_id,
        region=resource.region,
        evidence="Encrypted=false",
    )]


@rule_for(
    "aws_ebs_snapshot",
    check_id="EBS-003",
    service="EBS",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="EBS snapshot is publicly restorable",
    description="The snapshot's create-volume permissions explicitly include the public group. Public snapshot sharing can expose the underlying data to any AWS account.",
    remediation="Remove the public create-volume permission and review whether the snapshot contains sensitive data. Use narrowly scoped account sharing where required.",
)
def check_public_ebs_snapshot(resource: Resource) -> list[Finding]:
    if resource.attributes.get("public") is not True:
        return []
    return [Finding.from_rule(
        check_public_ebs_snapshot,
        resource=resource.resource_id,
        region=resource.region,
        evidence="CreateVolumePermissions includes Group=all",
    )]
