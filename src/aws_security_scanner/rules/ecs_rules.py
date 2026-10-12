from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_ecs_task_definition",
    check_id="ECS-001",
    service="ECS",
    severity=Severity.HIGH,
    category="Container Security",
    title="ECS task definition enables privileged containers",
    description=(
        "At least one container explicitly enables privileged mode, which "
        "can substantially weaken container isolation on supported launch types."
    ),
    remediation=(
        "Disable privileged mode unless a documented requirement justifies it. "
        "Prefer narrowly scoped capabilities and a dedicated task definition."
    ),
)
def check_ecs_privileged_container(resource: Resource) -> list[Finding]:
    """Detect containers explicitly configured as privileged."""
    containers = resource.attributes.get("containers", [])
    if not isinstance(containers, list):
        return []
    names = [
        str(container.get("name") or "<unnamed>")
        for container in containers
        if isinstance(container, dict) and container.get("privileged") is True
    ]
    if not names:
        return []
    return [Finding.from_rule(
        check_ecs_privileged_container,
        resource=resource.resource_id,
        region=resource.region,
        evidence="privileged containers: " + ", ".join(names),
    )]


@rule_for(
    "aws_ecs_task_definition",
    check_id="ECS-002",
    service="ECS",
    severity=Severity.HIGH,
    category="Network Isolation",
    title="ECS task definition uses host network mode",
    description=(
        "The task definition uses host networking, which reduces network "
        "isolation between the task and its underlying container instance."
    ),
    remediation=(
        "Prefer awsvpc networking where supported and validate any remaining "
        "host-network requirement against the workload's threat model."
    ),
)
def check_ecs_host_network_mode(resource: Resource) -> list[Finding]:
    """Detect ECS task definitions using host network mode."""
    if resource.attributes.get("network_mode") != "host":
        return []
    return [Finding.from_rule(
        check_ecs_host_network_mode,
        resource=resource.resource_id,
        region=resource.region,
        evidence="network_mode=host",
    )]


@rule_for(
    "aws_ecs_task_definition",
    check_id="ECS-003",
    service="ECS",
    severity=Severity.MEDIUM,
    category="Container Security",
    title="ECS container explicitly runs as root",
    description=(
        "A container explicitly sets its user to root (UID 0), increasing "
        "the impact of a container compromise."
    ),
    remediation=(
        "Configure the container to run as a dedicated non-root user and "
        "verify that the application functions with the reduced privileges."
    ),
)
def check_ecs_root_user(resource: Resource) -> list[Finding]:
    """Detect containers whose task definition explicitly selects root."""
    containers = resource.attributes.get("containers", [])
    if not isinstance(containers, list):
        return []
    names = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        user = container.get("user")
        if not isinstance(user, str):
            continue
        user_id = user.strip().split(":", 1)[0].lower()
        if user_id in {"root", "0"}:
            names.append(str(container.get("name") or "<unnamed>"))
    if not names:
        return []
    return [Finding.from_rule(
        check_ecs_root_user,
        resource=resource.resource_id,
        region=resource.region,
        evidence="containers explicitly running as root: " + ", ".join(names),
    )]


@rule_for(
    "aws_ecs_task_definition",
    check_id="ECS-004",
    service="ECS",
    severity=Severity.MEDIUM,
    category="Container Security",
    title="ECS container root filesystem is writable",
    description=(
        "At least one container explicitly allows writes to its root filesystem. "
        "A read-only root filesystem can reduce persistence opportunities after compromise."
    ),
    remediation=(
        "Set readonlyRootFilesystem to true where compatible, and provide "
        "explicit writable volumes for application paths that need them."
    ),
)
def check_ecs_root_filesystem_writable(resource: Resource) -> list[Finding]:
    """Detect containers whose root filesystem is explicitly writable."""
    containers = resource.attributes.get("containers", [])
    if not isinstance(containers, list):
        return []
    names = [
        str(container.get("name") or "<unnamed>")
        for container in containers
        if isinstance(container, dict)
        and container.get("readonly_root_filesystem") is False
    ]
    if not names:
        return []
    return [Finding.from_rule(
        check_ecs_root_filesystem_writable,
        resource=resource.resource_id,
        region=resource.region,
        evidence="writable root filesystem: " + ", ".join(names),
    )]


@rule_for(
    "aws_ecs_service",
    check_id="ECS-005",
    service="ECS",
    severity=Severity.MEDIUM,
    category="Network Exposure",
    title="ECS service assigns public IP addresses to tasks",
    description=(
        "The service's awsvpc network configuration explicitly assigns public "
        "IP addresses to tasks. This increases exposure; actual reachability "
        "also depends on routing and security-group rules."
    ),
    remediation=(
        "Disable public IP assignment unless required. Prefer private subnets, "
        "controlled ingress through a load balancer, and restrictive security groups."
    ),
)
def check_ecs_service_public_ip(resource: Resource) -> list[Finding]:
    """Detect ECS services that explicitly assign public IPs to tasks."""
    if str(resource.attributes.get("assign_public_ip", "")).upper() != "ENABLED":
        return []
    return [Finding.from_rule(
        check_ecs_service_public_ip,
        resource=resource.resource_id,
        region=resource.region,
        evidence="assign_public_ip=ENABLED",
    )]
