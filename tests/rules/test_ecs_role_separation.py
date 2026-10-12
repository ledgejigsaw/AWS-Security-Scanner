from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.ecs_rules import check_ecs_task_and_execution_roles_shared


def task_definition(**attributes):
    return Resource(
        resource_type="aws_ecs_task_definition",
        resource_id="arn:aws:ecs:eu-west-2:123456789012:task-definition/example:1",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_shared_explicit_task_and_execution_role_generates_informational_finding():
    role_arn = "arn:aws:iam::123456789012:role/example"
    findings = check_ecs_task_and_execution_roles_shared(task_definition(
        task_role_arn=role_arn,
        execution_role_arn=role_arn,
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "ECS-006"
    assert findings[0].severity == Severity.INFO
    assert role_arn in findings[0].evidence


def test_distinct_task_and_execution_roles_do_not_generate_finding():
    findings = check_ecs_task_and_execution_roles_shared(task_definition(
        task_role_arn="arn:aws:iam::123456789012:role/task",
        execution_role_arn="arn:aws:iam::123456789012:role/execution",
    ))
    assert findings == []


def test_missing_or_unknown_role_metadata_does_not_generate_finding():
    assert check_ecs_task_and_execution_roles_shared(task_definition(
        task_role_arn=None,
        execution_role_arn="arn:aws:iam::123456789012:role/execution",
    )) == []
    assert check_ecs_task_and_execution_roles_shared(task_definition(
        task_role_arn="arn:aws:iam::123456789012:role/task",
    )) == []
    assert check_ecs_task_and_execution_roles_shared(task_definition()) == []
