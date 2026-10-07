from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_subnet",
    check_id="VPC-001",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Subnet automatically assigns public IPv4 addresses",
    description=(
        "The subnet automatically assigns public IPv4 addresses "
        "to instances launched into it."
    ),
    remediation=(
        "Disable automatic public IPv4 address assignment unless "
        "the subnet is intentionally public."
    ),
)
def check_public_subnet(resource: Resource) -> list[Finding]:
    """Detect subnets that automatically assign public IPv4 addresses."""

    if resource.attributes.get("map_public_ip_on_launch") is not True:
        return []

    return [
        Finding.from_rule(
            check_public_subnet,
            resource=resource.resource_id,
            region=resource.region,
            evidence="map_public_ip_on_launch=true",
        )
    ]


@rule_for(
    "aws_route_table",
    check_id="VPC-002",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Route table exposes unrestricted IPv4 internet access",
    description=(
        "The route table contains a default IPv4 route "
        "to an Internet Gateway."
    ),
    remediation=(
        "Remove unnecessary Internet Gateway routes and use "
        "private routing or controlled egress where appropriate."
    ),
)
def check_unrestricted_ipv4_route(resource: Resource) -> list[Finding]:
    """Detect unrestricted IPv4 routes through an Internet Gateway."""

    for route in resource.attributes.get("routes", []):
        if (
            route.get("destination_cidr") == "0.0.0.0/0"
            and route.get("gateway_id", "").startswith("igw-")
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_ipv4_route,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "destination_cidr=0.0.0.0/0 "
                        "via Internet Gateway"
                    ),
                )
            ]

    return []


@rule_for(
    "aws_route_table",
    check_id="VPC-003",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Route table exposes unrestricted IPv6 internet access",
    description=(
        "The route table contains a default IPv6 route "
        "to an Internet Gateway."
    ),
    remediation=(
        "Remove unnecessary IPv6 Internet Gateway routes "
        "and use controlled egress where appropriate."
    ),
)
def check_unrestricted_ipv6_route(resource: Resource) -> list[Finding]:
    """Detect unrestricted IPv6 routes through an Internet Gateway."""

    for route in resource.attributes.get("routes", []):
        if (
            route.get("destination_ipv6") == "::/0"
            and route.get("gateway_id", "").startswith("igw-")
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_ipv6_route,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "destination_ipv6=::/0 "
                        "via Internet Gateway"
                    ),
                )
            ]

    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-004",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Network ACL allows unrestricted IPv4 ingress",
    description=(
        "The network ACL permits inbound IPv4 traffic "
        "from any Internet address."
    ),
    remediation=(
        "Restrict inbound network ACL rules to the required "
        "source CIDR ranges and ports."
    ),
)
def check_unrestricted_nacl_ingress(resource: Resource) -> list[Finding]:
    """Detect unrestricted IPv4 ingress in a network ACL."""

    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is False
            and entry.get("rule_action") == "allow"
            and entry.get("cidr_block") == "0.0.0.0/0"
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_nacl_ingress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence="ingress cidr_block=0.0.0.0/0",
                )
            ]

    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-005",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Network ACL allows unrestricted IPv4 egress",
    description=(
        "The network ACL permits outbound IPv4 traffic "
        "to any Internet address."
    ),
    remediation=(
        "Restrict outbound network ACL rules to the required "
        "destination CIDR ranges and ports."
    ),
)
def check_unrestricted_nacl_egress(resource: Resource) -> list[Finding]:
    """Detect unrestricted IPv4 egress in a network ACL."""

    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is True
            and entry.get("rule_action") == "allow"
            and entry.get("cidr_block") == "0.0.0.0/0"
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_nacl_egress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence="egress cidr_block=0.0.0.0/0",
                )
            ]

    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-006",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Network ACL allows unrestricted IPv6 ingress",
    description=(
        "The network ACL permits inbound IPv6 traffic "
        "from any Internet address."
    ),
    remediation=(
        "Restrict inbound IPv6 network ACL rules to the required "
        "source CIDR ranges and ports."
    ),
)
def check_unrestricted_nacl_ipv6_ingress(
    resource: Resource,
) -> list[Finding]:
    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is False
            and entry.get("rule_action") == "allow"
            and entry.get("ipv6_cidr_block") == "::/0"
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_nacl_ipv6_ingress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence="ingress ipv6_cidr_block=::/0",
                )
            ]
    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-007",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Network ACL allows unrestricted IPv6 egress",
    description=(
        "The network ACL permits outbound IPv6 traffic "
        "to any Internet address."
    ),
    remediation=(
        "Restrict outbound IPv6 network ACL rules to the required "
        "destination CIDR ranges and ports."
    ),
)
def check_unrestricted_nacl_ipv6_egress(
    resource: Resource,
) -> list[Finding]:
    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is True
            and entry.get("rule_action") == "allow"
            and entry.get("ipv6_cidr_block") == "::/0"
        ):
            return [
                Finding.from_rule(
                    check_unrestricted_nacl_ipv6_egress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence="egress ipv6_cidr_block=::/0",
                )
            ]
    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-008",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Default network ACL allows unrestricted IPv4 ingress",
    description=(
        "The default network ACL permits inbound IPv4 traffic "
        "from any Internet address."
    ),
    remediation=(
        "Restrict the default network ACL to required source "
        "CIDR ranges and ports."
    ),
)
def check_default_nacl_ingress(
    resource: Resource,
) -> list[Finding]:
    if resource.attributes.get("is_default") is not True:
        return []

    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is False
            and entry.get("rule_action") == "allow"
            and entry.get("cidr_block") == "0.0.0.0/0"
        ):
            return [
                Finding.from_rule(
                    check_default_nacl_ingress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "default NACL ingress "
                        "cidr_block=0.0.0.0/0"
                    ),
                )
            ]
    return []


@rule_for(
    "aws_network_acl",
    check_id="VPC-009",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Default network ACL allows unrestricted IPv4 egress",
    description=(
        "The default network ACL permits outbound IPv4 traffic "
        "to any Internet address."
    ),
    remediation=(
        "Restrict the default network ACL to required destination "
        "CIDR ranges and ports."
    ),
)
def check_default_nacl_egress(
    resource: Resource,
) -> list[Finding]:
    if resource.attributes.get("is_default") is not True:
        return []

    for entry in resource.attributes.get("entries", []):
        if (
            entry.get("egress") is True
            and entry.get("rule_action") == "allow"
            and entry.get("cidr_block") == "0.0.0.0/0"
        ):
            return [
                Finding.from_rule(
                    check_default_nacl_egress,
                    resource=resource.resource_id,
                    region=resource.region,
                    evidence=(
                        "default NACL egress "
                        "cidr_block=0.0.0.0/0"
                    ),
                )
            ]
    return []


@rule_for(
    "aws_route_table",
    check_id="VPC-010",
    service="VPC",
    severity=Severity.HIGH,
    category="Network Security",
    title="Associated subnet has unrestricted IPv4 Internet routing",
    description=(
        "A subnet associated with this route table has a default "
        "IPv4 route directly to an Internet Gateway."
    ),
    remediation=(
        "Remove unnecessary Internet Gateway routes from associated "
        "private subnets and use controlled routing where appropriate."
    ),
)
def check_associated_public_route(
    resource: Resource,
) -> list[Finding]:
    has_public_route = any(
        route.get("destination_cidr") == "0.0.0.0/0"
        and route.get("gateway_id", "").startswith("igw-")
        for route in resource.attributes.get("routes", [])
    )

    if not has_public_route:
        return []

    subnet_ids = [
        association.get("subnet_id")
        for association in resource.attributes.get("associations", [])
        if association.get("subnet_id")
    ]

    if not subnet_ids:
        return []

    return [
        Finding.from_rule(
            check_associated_public_route,
            resource=resource.resource_id,
            region=resource.region,
            evidence=(
                "0.0.0.0/0 via Internet Gateway "
                f"associated_subnets={','.join(subnet_ids)}"
            ),
        )
    ]