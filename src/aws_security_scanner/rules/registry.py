from aws_security_scanner.rules.s3_rules import (
    check_public_bucket,
    check_encryption,
    check_versioning,
    check_block_public_access,
    check_logging,
    check_wildcard_bucket_policy,
    check_tls_enforcement,
    check_excessive_s3_actions,
    check_wildcard_bucket_resource,
)

from aws_security_scanner.rules.iam_rules import (
    check_overly_permissive_policy,
    check_wildcard_permissions,
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
)

def get_all_rules():
    """Return all registered security rules."""

    return [
        check_public_bucket,
        check_encryption,
        check_versioning,
        check_block_public_access,
        check_logging,
        check_wildcard_bucket_policy,
        check_tls_enforcement,
        check_excessive_s3_actions,
        check_wildcard_bucket_resource,
        check_overly_permissive_policy,
        check_wildcard_permissions,
        check_excessive_administrative_permissions,
        check_insecure_trust_policy,
    ]