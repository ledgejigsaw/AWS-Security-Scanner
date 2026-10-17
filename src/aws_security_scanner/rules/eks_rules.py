from ipaddress import ip_network

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_eks_cluster",
    check_id="EKS-001",
    service="EKS",
    severity=Severity.HIGH,
    category="Network Exposure",
    title="EKS public API endpoint allows access from any IPv4 or IPv6 address",
    description="The EKS Kubernetes API endpoint is public and its configured CIDR allow-list includes an unrestricted IPv4 or IPv6 network.",
    remediation="Restrict public access CIDRs to approved administration networks and prefer private endpoint access where operationally appropriate.",
)
def check_eks_unrestricted_public_endpoint(resource: Resource) -> list[Finding]:
    if resource.attributes.get("endpoint_public_access") is not True:
        return []
    cidrs = resource.attributes.get("public_access_cidrs", [])
    if not isinstance(cidrs, list):
        return []
    unrestricted = []
    for cidr in cidrs:
        if not isinstance(cidr, str):
            continue
        try:
            network = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            unrestricted.append(cidr)
    if not unrestricted:
        return []
    return [Finding.from_rule(
        check_eks_unrestricted_public_endpoint,
        resource=resource.resource_id,
        region=resource.region,
        evidence="endpoint_public_access=true; public_access_cidrs=" + ",".join(sorted(unrestricted)),
    )]


@rule_for(
    "aws_eks_cluster",
    check_id="EKS-002",
    service="EKS",
    severity=Severity.MEDIUM,
    category="Logging and Monitoring",
    title="EKS control-plane audit logging is not enabled",
    description="The discovered EKS cluster configuration does not explicitly enable the audit control-plane log type.",
    remediation="Enable the EKS audit control-plane log type and review log destination, retention and access controls.",
)
def check_eks_audit_logging_disabled(resource: Resource) -> list[Finding]:
    observed = resource.attributes.get("control_plane_log_types_observed")
    enabled = resource.attributes.get("control_plane_log_types_enabled")
    if not isinstance(observed, list) or not isinstance(enabled, list):
        return []
    if "audit" not in observed:
        return []
    if "audit" in enabled:
        return []
    # EKS returns configured types and enabled state; absent logging metadata is
    # unknown rather than a confirmed disabled setting.
    return [Finding.from_rule(
        check_eks_audit_logging_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence="control_plane_log_types_observed=" + ",".join(sorted(observed)) + "; enabled=" + ",".join(sorted(enabled)),
    )]


@rule_for(
    "aws_eks_cluster",
    check_id="EKS-003",
    service="EKS",
    severity=Severity.INFO,
    category="Network Exposure",
    title="EKS cluster has no private API endpoint",
    description="The Kubernetes API endpoint is public and private endpoint access is explicitly disabled. This is a review signal rather than proof of reachability.",
    remediation="Consider enabling private endpoint access for approved administrative workflows and restrict public endpoint CIDRs where public access remains necessary.",
)
def check_eks_public_endpoint_review(resource: Resource) -> list[Finding]:
    if resource.attributes.get("endpoint_public_access") is not True:
        return []
    if resource.attributes.get("endpoint_private_access") is not False:
        return []
    cidrs = resource.attributes.get("public_access_cidrs")
    if not isinstance(cidrs, list):
        return []
    return [Finding.from_rule(
        check_eks_public_endpoint_review,
        resource=resource.resource_id,
        region=resource.region,
        evidence="endpoint_public_access=true; endpoint_private_access=false; public_access_cidrs=" + ",".join(sorted(str(item) for item in cidrs)),
    )]
