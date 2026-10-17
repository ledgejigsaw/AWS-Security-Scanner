from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_efs_file_system",
    check_id="EFS-001",
    service="EFS",
    severity=Severity.MEDIUM,
    category="Data Protection",
    title="EFS file system is explicitly unencrypted",
    description="The discovered EFS file-system metadata explicitly reports that encryption at rest is disabled.",
    remediation="Create an encrypted file system and plan a controlled data migration if the existing file system cannot be encrypted in place.",
)
def check_efs_encryption_disabled(resource: Resource) -> list[Finding]:
    if resource.attributes.get("encrypted") is not False:
        return []
    return [Finding.from_rule(
        check_efs_encryption_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence="encrypted=false",
    )]


@rule_for(
    "aws_efs_access_point",
    check_id="EFS-002",
    service="EFS",
    severity=Severity.INFO,
    category="Access Control",
    title="EFS access point explicitly maps clients to UID 0",
    description="The access point POSIX identity explicitly uses UID 0. This can be intentional, but should be reviewed against the workload's least-privilege requirements.",
    remediation="Use a dedicated non-root POSIX identity where compatible and verify file ownership and permissions before changing access-point settings.",
)
def check_efs_access_point_root_identity(resource: Resource) -> list[Finding]:
    posix_user = resource.attributes.get("posix_user")
    if not isinstance(posix_user, dict):
        return []
    uid = posix_user.get("Uid")
    if uid != 0 and str(uid) != "0":
        return []
    return [Finding.from_rule(
        check_efs_access_point_root_identity,
        resource=resource.resource_id,
        region=resource.region,
        evidence="posix_user_uid=0",
    )]
