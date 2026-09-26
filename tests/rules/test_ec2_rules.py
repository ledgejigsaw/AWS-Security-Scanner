from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.ec2_rules import (
    check_ssh_exposed,
    check_rdp_exposed,
    check_sensitive_port_exposed,
    check_unrestricted_ingress,
    check_unrestricted_egress,
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