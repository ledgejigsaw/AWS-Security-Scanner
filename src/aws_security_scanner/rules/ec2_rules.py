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