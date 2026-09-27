from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


INTERNET_CIDRS = {
    "0.0.0.0/0",
    "::/0",
}

SENSITIVE_PORTS = {
    21,      # FTP
    23,      # Telnet
    25,      # SMTP
    3306,    # MySQL
    5432,    # PostgreSQL
    6379,    # Redis
    9200,    # Elasticsearch
    27017,   # MongoDB
}


def _is_internet_exposed(rule: dict) -> bool:
    """Return True when a security-group rule allows traffic from anywhere."""
    return rule.get("cidr") in INTERNET_CIDRS


@rule_for(
    "aws_security_group",
    check_id="EC2-001",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="SSH is exposed to the Internet",
    description=(
        "The security group allows inbound SSH traffic from "
        "the public Internet."
    ),
    remediation=(
        "Restrict SSH access to trusted IP ranges, VPNs, or "
        "other controlled management networks."
    ),
)
def check_ssh_exposed(resource: Resource) -> list[Finding]:
    """Detect Internet-exposed SSH access."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if (
            rule.get("protocol") == "tcp"
            and rule.get("from_port") <= 22 <= rule.get("to_port")
            and _is_internet_exposed(rule)
        ):
            findings.append(
                Finding.from_rule(
                    check_ssh_exposed,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"TCP port range "
                        f"{rule.get('from_port')}-{rule.get('to_port')} "
                        f"allows access from {rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-002",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="RDP is exposed to the Internet",
    description=(
        "The security group allows inbound RDP traffic from "
        "the public Internet."
    ),
    remediation=(
        "Restrict RDP access to trusted IP ranges, VPNs, or "
        "other controlled management networks."
    ),
)
def check_rdp_exposed(resource: Resource) -> list[Finding]:
    """Detect Internet-exposed RDP access."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if (
            rule.get("protocol") == "tcp"
            and rule.get("from_port") <= 3389 <= rule.get("to_port")
            and _is_internet_exposed(rule)
        ):
            findings.append(
                Finding.from_rule(
                    check_rdp_exposed,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"TCP port range "
                        f"{rule.get('from_port')}-{rule.get('to_port')} "
                        f"allows access from {rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-003",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="Sensitive service port is exposed to the Internet",
    description=(
        "The security group allows inbound access to a "
        "sensitive service port from the public Internet."
    ),
    remediation=(
        "Restrict access to sensitive service ports to trusted "
        "networks and required source addresses."
    ),
)
def check_sensitive_port_exposed(resource: Resource) -> list[Finding]:
    """Detect Internet exposure of commonly sensitive service ports."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if not _is_internet_exposed(rule):
            continue

        if rule.get("protocol") != "tcp":
            continue

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        if from_port is None or to_port is None:
            continue

        exposed_ports = [
            port
            for port in SENSITIVE_PORTS
            if from_port <= port <= to_port
        ]

        if exposed_ports:
            findings.append(
                Finding.from_rule(
                    check_sensitive_port_exposed,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"Sensitive ports {exposed_ports} "
                        f"are accessible from {rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-004",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="Inbound traffic is unrestricted",
    description=(
        "The security group allows all inbound protocols and "
        "ports from the public Internet."
    ),
    remediation=(
        "Restrict inbound traffic to the protocols, ports, "
        "and source networks that are actually required."
    ),
)
def check_unrestricted_ingress(resource: Resource) -> list[Finding]:
    """Detect unrestricted Internet inbound access."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if (
            rule.get("protocol") == "-1"
            and _is_internet_exposed(rule)
        ):
            findings.append(
                Finding.from_rule(
                    check_unrestricted_ingress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "All inbound protocols and ports are "
                        f"allowed from {rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-005",
    service="EC2",
    severity=Severity.MEDIUM,
    category="Network Security",
    title="Outbound traffic is unrestricted",
    description=(
        "The security group allows all outbound protocols and "
        "ports to the public Internet."
    ),
    remediation=(
        "Restrict outbound traffic where practical to the "
        "destinations and services required by the workload."
    ),
)
def check_unrestricted_egress(resource: Resource) -> list[Finding]:
    """Detect unrestricted Internet outbound access."""

    findings = []

    for rule in resource.attributes.get("egress_rules", []):
        if (
            rule.get("protocol") == "-1"
            and _is_internet_exposed(rule)
        ):
            findings.append(
                Finding.from_rule(
                    check_unrestricted_egress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "All outbound protocols and ports are "
                        f"allowed to {rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings

@rule_for(
    "aws_instance",
    check_id="EC2-006",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="EC2 instance has a public IPv4 address",
    description=(
        "The EC2 instance has a public IPv4 address and may "
        "be directly reachable from the Internet."
    ),
    remediation=(
        "Remove unnecessary public IP addresses and place "
        "instances behind controlled network boundaries."
    ),
)
def check_public_ipv4(resource: Resource) -> list[Finding]:
    """Detect EC2 instances with a public IPv4 address."""

    findings = []

    public_ip = resource.attributes.get("public_ip_address")

    if public_ip:
        findings.append(
            Finding.from_rule(
                check_public_ipv4,
                resource=resource.resource_id,
                region=resource.region,
                evidence=f"Public IPv4 address: {public_ip}",
            )
        )

    return findings


@rule_for(
    "aws_instance",
    check_id="EC2-007",
    service="EC2",
    severity=Severity.HIGH,
    category="Instance Security",
    title="EC2 instance allows IMDSv1",
    description=(
        "The EC2 instance metadata service allows IMDSv1 "
        "requests."
    ),
    remediation=(
        "Require IMDSv2 by configuring HttpTokens to "
        "required."
    ),
)
def check_imdsv1_enabled(resource: Resource) -> list[Finding]:
    """Detect EC2 instances that permit IMDSv1."""

    findings = []

    metadata_options = resource.attributes.get(
        "metadata_options",
        {},
    )

    http_tokens = metadata_options.get("http_tokens")

    if http_tokens == "optional":
        findings.append(
            Finding.from_rule(
                check_imdsv1_enabled,
                resource=resource.resource_id,
                region=resource.region,
                evidence="HttpTokens=optional",
            )
        )

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-008",
    service="EC2",
    severity=Severity.HIGH,
    category="Network Security",
    title="Security group allows unrestricted IPv6 ingress",
    description=(
        "The security group allows inbound traffic from "
        "the entire IPv6 Internet."
    ),
    remediation=(
        "Restrict IPv6 inbound traffic to the specific "
        "networks and ports required."
    ),
)
def check_unrestricted_ipv6_ingress(
    resource: Resource,
) -> list[Finding]:
    """Detect unrestricted IPv6 inbound access."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if (
            rule.get("cidr") == "::/0"
            and rule.get("protocol") != ""
        ):
            findings.append(
                Finding.from_rule(
                    check_unrestricted_ipv6_ingress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"IPv6 ingress allowed from "
                        f"{rule.get('cidr')}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-009",
    service="EC2",
    severity=Severity.MEDIUM,
    category="Network Security",
    title="Security group allows a broad port range",
    description=(
        "The security group allows inbound traffic across "
        "a broad range of TCP ports."
    ),
    remediation=(
        "Restrict inbound access to only the ports required "
        "by the workload."
    ),
)
def check_broad_port_range(resource: Resource) -> list[Finding]:
    """Detect unusually broad TCP port ranges."""

    findings = []

    for rule in resource.attributes.get("ingress_rules", []):
        if rule.get("protocol") != "tcp":
            continue

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        if from_port is None or to_port is None:
            continue

        if to_port - from_port >= 1000:
            findings.append(
                Finding.from_rule(
                    check_broad_port_range,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        f"TCP port range "
                        f"{from_port}-{to_port}"
                    ),
                )
            )
            break

    return findings


@rule_for(
    "aws_security_group",
    check_id="EC2-010",
    service="EC2",
    severity=Severity.MEDIUM,
    category="Network Security",
    title="Security group allows unrestricted IPv6 egress",
    description=(
        "The security group allows all outbound traffic "
        "to the IPv6 Internet."
    ),
    remediation=(
        "Restrict outbound IPv6 traffic where practical to "
        "the destinations and services required."
    ),
)
def check_unrestricted_ipv6_egress(
    resource: Resource,
) -> list[Finding]:
    """Detect unrestricted IPv6 outbound access."""

    findings = []

    for rule in resource.attributes.get("egress_rules", []):
        if (
            rule.get("protocol") == "-1"
            and rule.get("cidr") == "::/0"
        ):
            findings.append(
                Finding.from_rule(
                    check_unrestricted_ipv6_egress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "All outbound protocols and ports "
                        "allowed to ::/0"
                    ),
                )
            )
            break

    return findings