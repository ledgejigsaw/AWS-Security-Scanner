import json
from pathlib import Path

from aws_security_scanner.models.resource import Resource
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


FIXTURE_DIR = Path("tests/fixtures/vpc")


def load_fixture(filename):
    with (FIXTURE_DIR / filename).open() as file:
        return json.load(file)


def test_public_subnet_generates_high_finding():
    data = load_fixture("insecure_subnet.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["subnet_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_public_subnet(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-001"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "subnet-public01"


def test_private_subnet_does_not_generate_finding():
    data = load_fixture("secure_subnet.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["subnet_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_public_subnet(resource)

    assert findings == []


def test_unrestricted_ipv4_route_generates_high_finding():
    data = load_fixture("insecure_route_table.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["route_table_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_unrestricted_ipv4_route(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-002"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "rtb-public01"


def test_unrestricted_ipv6_route_generates_high_finding():
    data = load_fixture("insecure_route_table.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["route_table_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_unrestricted_ipv6_route(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-003"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "rtb-public01"


def test_secure_route_table_does_not_generate_findings():
    data = load_fixture("secure_route_table.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["route_table_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    assert check_unrestricted_ipv4_route(resource) == []
    assert check_unrestricted_ipv6_route(resource) == []


def test_unrestricted_nacl_ingress_generates_high_finding():
    data = load_fixture("insecure_network_acl.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["network_acl_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_unrestricted_nacl_ingress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-004"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "acl-insecure01"


def test_unrestricted_nacl_egress_generates_high_finding():
    data = load_fixture("insecure_network_acl.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["network_acl_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    findings = check_unrestricted_nacl_egress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-005"
    assert findings[0].severity == "HIGH"
    assert findings[0].resource == "acl-insecure01"


def test_secure_network_acl_does_not_generate_findings():
    data = load_fixture("secure_network_acl.json")

    resource = Resource(
        resource_type=data["resource_type"],
        resource_id=data["network_acl_id"],
        attributes=data,
        source="fixture",
        region=data["region"],
    )

    assert check_unrestricted_nacl_ingress(resource) == []
    assert check_unrestricted_nacl_egress(resource) == []

def test_unrestricted_ipv6_nacl_ingress_generates_high_finding():
    resource = Resource(
        resource_type="aws_network_acl",
        resource_id="acl-ipv6-insecure01",
        attributes={
            "entries": [
                {
                    "egress": False,
                    "rule_action": "allow",
                    "ipv6_cidr_block": "::/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_nacl_ipv6_ingress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-006"
    assert findings[0].severity.value == "HIGH"


def test_unrestricted_ipv6_nacl_egress_generates_high_finding():
    resource = Resource(
        resource_type="aws_network_acl",
        resource_id="acl-ipv6-insecure01",
        attributes={
            "entries": [
                {
                    "egress": True,
                    "rule_action": "allow",
                    "ipv6_cidr_block": "::/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_nacl_ipv6_egress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-007"
    assert findings[0].severity.value == "HIGH"


def test_default_nacl_ingress_generates_high_finding():
    resource = Resource(
        resource_type="aws_network_acl",
        resource_id="acl-default-insecure01",
        attributes={
            "is_default": True,
            "entries": [
                {
                    "egress": False,
                    "rule_action": "allow",
                    "cidr_block": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_default_nacl_ingress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-008"
    assert findings[0].severity.value == "HIGH"


def test_default_nacl_egress_generates_high_finding():
    resource = Resource(
        resource_type="aws_network_acl",
        resource_id="acl-default-insecure01",
        attributes={
            "is_default": True,
            "entries": [
                {
                    "egress": True,
                    "rule_action": "allow",
                    "cidr_block": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_default_nacl_egress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-009"
    assert findings[0].severity.value == "HIGH"


def test_associated_public_route_generates_high_finding():
    resource = Resource(
        resource_type="aws_route_table",
        resource_id="rtb-public01",
        attributes={
            "routes": [
                {
                    "destination_cidr": "0.0.0.0/0",
                    "gateway_id": "igw-security01",
                }
            ],
            "associations": [
                {
                    "subnet_id": "subnet-public01",
                }
            ],
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_associated_public_route(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "VPC-010"
    assert findings[0].severity.value == "HIGH"