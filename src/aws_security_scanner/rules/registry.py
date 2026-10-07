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
    check_public_write_access,
)

from aws_security_scanner.rules.iam_rules import (
    check_overly_permissive_policy,
    check_wildcard_permissions,
    check_excessive_administrative_permissions,
    check_insecure_trust_policy,
)


from aws_security_scanner.rules.ec2_rules import (
    check_ssh_exposed,
    check_rdp_exposed,
    check_sensitive_port_exposed,
    check_unrestricted_ingress,
    check_unrestricted_egress,
    check_public_ipv4,
    check_imdsv1_enabled,
    check_unrestricted_ipv6_ingress,
    check_broad_port_range,
    check_unrestricted_ipv6_egress,
)

from aws_security_scanner.rules.vpc_rules import (
    check_public_subnet,
    check_unrestricted_ipv4_route,
    check_unrestricted_ipv6_route,
    check_unrestricted_nacl_ingress,
    check_unrestricted_nacl_egress,
    check_unrestricted_nacl_ipv6_ingress,
    check_unrestricted_nacl_ipv6_egress,
    check_default_nacl_ingress,
    check_default_nacl_egress,
    check_associated_public_route,
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
        check_public_write_access,
        check_overly_permissive_policy,
        check_wildcard_permissions,
        check_excessive_administrative_permissions,
        check_insecure_trust_policy,
        check_ssh_exposed,
        check_rdp_exposed,
        check_sensitive_port_exposed,
        check_unrestricted_ingress,
        check_unrestricted_egress,
        check_public_ipv4,
        check_imdsv1_enabled,
        check_unrestricted_ipv6_ingress,
        check_broad_port_range,
        check_unrestricted_ipv6_egress,
        check_public_subnet,
        check_unrestricted_ipv4_route,
        check_unrestricted_ipv6_route,
        check_unrestricted_nacl_ingress,
        check_unrestricted_nacl_egress,
        check_unrestricted_nacl_ipv6_ingress,
        check_unrestricted_nacl_ipv6_egress,
        check_default_nacl_ingress,
        check_default_nacl_egress,
        check_associated_public_route,
    ]