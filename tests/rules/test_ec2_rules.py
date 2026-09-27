from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
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


def test_ssh_exposed_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-ssh-open",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_ssh_exposed(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-001"
    assert findings[0].severity == Severity.HIGH


def test_rdp_exposed_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-rdp-open",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_rdp_exposed(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-002"
    assert findings[0].severity == Severity.HIGH


def test_sensitive_port_exposed_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-sensitive-port",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 3306,
                    "to_port": 3306,
                    "cidr": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_sensitive_port_exposed(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-003"
    assert findings[0].severity == Severity.HIGH


def test_unrestricted_ingress_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-unrestricted-ingress",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "-1",
                    "from_port": 0,
                    "to_port": 0,
                    "cidr": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_ingress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-004"
    assert findings[0].severity == Severity.HIGH


def test_unrestricted_egress_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-unrestricted-egress",
        attributes={
            "egress_rules": [
                {
                    "protocol": "-1",
                    "from_port": 0,
                    "to_port": 0,
                    "cidr": "0.0.0.0/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_egress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-005"
    assert findings[0].severity == Severity.MEDIUM

def test_public_ipv4_generates_finding():
    resource = Resource(
        resource_type="aws_instance",
        resource_id="i-public",
        attributes={
            "public_ip_address": "203.0.113.10",
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_public_ipv4(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-006"
    assert findings[0].severity == Severity.HIGH


def test_imdsv1_enabled_generates_finding():
    resource = Resource(
        resource_type="aws_instance",
        resource_id="i-imdsv1",
        attributes={
            "metadata_options": {
                "http_tokens": "optional",
            }
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_imdsv1_enabled(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-007"
    assert findings[0].severity == Severity.HIGH


def test_unrestricted_ipv6_ingress_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-ipv6-open",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 443,
                    "to_port": 443,
                    "cidr": "::/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_ipv6_ingress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-008"
    assert findings[0].severity == Severity.HIGH


def test_broad_port_range_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-broad-range",
        attributes={
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 1,
                    "to_port": 1024,
                    "cidr": "10.0.0.0/8",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_broad_port_range(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-009"
    assert findings[0].severity == Severity.MEDIUM


def test_unrestricted_ipv6_egress_generates_finding():
    resource = Resource(
        resource_type="aws_security_group",
        resource_id="sg-ipv6-egress",
        attributes={
            "egress_rules": [
                {
                    "protocol": "-1",
                    "from_port": 0,
                    "to_port": 0,
                    "cidr": "::/0",
                }
            ]
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_unrestricted_ipv6_egress(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-010"
    assert findings[0].severity == Severity.MEDIUM