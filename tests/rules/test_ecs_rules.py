from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.ecs_rules import (
    check_ecs_host_network_mode,
    check_ecs_privileged_container,
    check_ecs_root_filesystem_writable,
    check_ecs_root_user,
    check_ecs_service_public_ip,
)


def task_definition(**attributes):
    return Resource(
        resource_type="aws_ecs_task_definition",
        resource_id="arn:aws:ecs:eu-west-2:123456789012:task-definition/app:1",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_privileged_container_generates_high_finding():
    findings = check_ecs_privileged_container(task_definition(
        containers=[{"name": "app", "privileged": True}]
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-001"
    assert findings[0].severity == Severity.HIGH
    assert "app" in findings[0].evidence


def test_privileged_container_false_or_unknown_is_not_flagged():
    assert check_ecs_privileged_container(task_definition(
        containers=[{"name": "app", "privileged": False}]
    )) == []
    assert check_ecs_privileged_container(task_definition()) == []


def test_host_network_mode_generates_high_finding():
    findings = check_ecs_host_network_mode(task_definition(network_mode="host"))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-002"
    assert findings[0].severity == Severity.HIGH


def test_non_host_or_unknown_network_mode_is_not_flagged():
    assert check_ecs_host_network_mode(task_definition(network_mode="awsvpc")) == []
    assert check_ecs_host_network_mode(task_definition()) == []


def test_explicit_root_user_generates_medium_finding():
    findings = check_ecs_root_user(task_definition(
        containers=[{"name": "worker", "user": "0:0"}]
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-003"
    assert findings[0].severity == Severity.MEDIUM


def test_non_root_or_unknown_user_is_not_flagged():
    assert check_ecs_root_user(task_definition(
        containers=[{"name": "worker", "user": "10001"}]
    )) == []
    assert check_ecs_root_user(task_definition(
        containers=[{"name": "worker"}]
    )) == []


def test_writable_root_filesystem_generates_medium_finding():
    findings = check_ecs_root_filesystem_writable(task_definition(
        containers=[{"name": "worker", "readonly_root_filesystem": False}]
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-004"
    assert findings[0].severity == Severity.MEDIUM


def test_readonly_or_unknown_root_filesystem_is_not_flagged():
    assert check_ecs_root_filesystem_writable(task_definition(
        containers=[{"name": "worker", "readonly_root_filesystem": True}]
    )) == []
    assert check_ecs_root_filesystem_writable(task_definition(
        containers=[{"name": "worker"}]
    )) == []


def test_ecs_service_public_ip_generates_medium_finding():
    resource = Resource(
        resource_type="aws_ecs_service",
        resource_id="arn:aws:ecs:eu-west-2:123456789012:service/cluster/web",
        attributes={"assign_public_ip": "ENABLED"},
        source="fixture",
        region="eu-west-2",
    )
    findings = check_ecs_service_public_ip(resource)
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-005"
    assert findings[0].severity == Severity.MEDIUM


def test_ecs_service_without_public_ip_is_not_flagged():
    resource = Resource(
        resource_type="aws_ecs_service",
        resource_id="service/web",
        attributes={"assign_public_ip": "DISABLED"},
        source="fixture",
        region="eu-west-2",
    )
    assert check_ecs_service_public_ip(resource) == []


def test_ecs_mutable_image_tag_generates_low_supply_chain_signal():
    from aws_security_scanner.rules.ecs_rules import check_ecs_image_not_pinned_by_digest

    findings = check_ecs_image_not_pinned_by_digest(task_definition(
        containers=[{"name": "api", "image": "123456789012.dkr.ecr.eu-west-2.amazonaws.com/api:latest"}]
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-007"
    assert findings[0].severity == Severity.LOW
    assert "api:latest" in findings[0].evidence


def test_ecs_digest_pinned_and_unknown_images_are_not_flagged():
    from aws_security_scanner.rules.ecs_rules import check_ecs_image_not_pinned_by_digest

    assert check_ecs_image_not_pinned_by_digest(task_definition(
        containers=[{"name": "api", "image": "repo/api@sha256:0123456789abcdef"}]
    )) == []
    assert check_ecs_image_not_pinned_by_digest(task_definition(containers=[{"name": "api"}])) == []
    assert check_ecs_image_not_pinned_by_digest(task_definition()) == []


def test_ecs_mutable_image_tag_generates_low_supply_chain_signal():
    from aws_security_scanner.rules.ecs_rules import check_ecs_image_not_pinned_by_digest

    findings = check_ecs_image_not_pinned_by_digest(task_definition(
        containers=[{"name": "api", "image": "123456789012.dkr.ecr.eu-west-2.amazonaws.com/api:latest"}]
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-007"
    assert findings[0].severity == Severity.LOW
    assert "api:latest" in findings[0].evidence


def test_ecs_digest_pinned_and_unknown_images_are_not_flagged():
    from aws_security_scanner.rules.ecs_rules import check_ecs_image_not_pinned_by_digest

    assert check_ecs_image_not_pinned_by_digest(task_definition(
        containers=[{"name": "api", "image": "repo/api@sha256:0123456789abcdef"}]
    )) == []
    assert check_ecs_image_not_pinned_by_digest(task_definition(containers=[{"name": "api"}])) == []
    assert check_ecs_image_not_pinned_by_digest(task_definition()) == []
