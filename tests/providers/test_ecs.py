from unittest.mock import Mock, call

from aws_security_scanner.providers.aws import AWSProvider


def test_ecs_task_definition_discovery_normalises_container_security_settings():
    client = Mock()
    client.list_task_definitions.return_value = {
        "taskDefinitionArns": [
            "arn:aws:ecs:eu-west-2:123456789012:task-definition/web:3"
        ]
    }
    client.describe_task_definition.return_value = {
        "taskDefinition": {
            "taskDefinitionArn": "arn:aws:ecs:eu-west-2:123456789012:task-definition/web:3",
            "family": "web",
            "revision": 3,
            "status": "ACTIVE",
            "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"],
            "taskRoleArn": "arn:aws:iam::123456789012:role/app",
            "containerDefinitions": [{
                "name": "web",
                "privileged": False,
                "user": "10001",
                "readonlyRootFilesystem": True,
            }],
        }
    }
    resources = AWSProvider(ecs_client=client, region="eu-west-2").discover_ecs_task_definitions()
    assert len(resources) == 1
    task = resources[0]
    assert task.resource_type == "aws_ecs_task_definition"
    assert task.attributes["requires_compatibilities"] == ["FARGATE"]
    assert task.attributes["containers"] == [{
        "name": "web",
        "privileged": False,
        "user": "10001",
        "readonly_root_filesystem": True,
        "essential": None,
    }]
    client.list_task_definitions.assert_called_once_with(status="ACTIVE", sort="DESC")
    client.describe_task_definition.assert_called_once_with(
        taskDefinition="arn:aws:ecs:eu-west-2:123456789012:task-definition/web:3"
    )


def test_ecs_task_definition_discovery_paginates():
    client = Mock()
    client.list_task_definitions.side_effect = [
        {"taskDefinitionArns": ["arn:task/one"], "nextToken": "next"},
        {"taskDefinitionArns": ["arn:task/two"]},
    ]
    client.describe_task_definition.side_effect = [
        {"taskDefinition": {"taskDefinitionArn": "arn:task/one", "containerDefinitions": []}},
        {"taskDefinition": {"taskDefinitionArn": "arn:task/two", "containerDefinitions": []}},
    ]
    resources = AWSProvider(ecs_client=client).discover_ecs_task_definitions()
    assert [item.resource_id for item in resources] == ["arn:task/one", "arn:task/two"]
    assert client.list_task_definitions.call_args_list == [
        call(status="ACTIVE", sort="DESC"),
        call(status="ACTIVE", sort="DESC", nextToken="next"),
    ]


def test_ecs_service_discovery_normalises_network_configuration():
    client = Mock()
    client.list_clusters.return_value = {"clusterArns": ["arn:cluster/prod"]}
    client.list_services.return_value = {"serviceArns": ["arn:service/web"]}
    client.describe_services.return_value = {"services": [{
        "serviceArn": "arn:service/web",
        "serviceName": "web",
        "clusterArn": "arn:cluster/prod",
        "status": "ACTIVE",
        "launchType": "FARGATE",
        "taskDefinition": "arn:task/web:1",
        "desiredCount": 2,
        "networkConfiguration": {"awsvpcConfiguration": {
            "assignPublicIp": "ENABLED",
            "subnets": ["subnet-123"],
            "securityGroups": ["sg-123"],
        }},
    }]}
    resources = AWSProvider(ecs_client=client, region="eu-west-2").discover_ecs_services()
    assert len(resources) == 1
    service = resources[0]
    assert service.resource_type == "aws_ecs_service"
    assert service.attributes["assign_public_ip"] == "ENABLED"
    assert service.attributes["subnets"] == ["subnet-123"]
    client.describe_services.assert_called_once_with(
        cluster="arn:cluster/prod", services=["arn:service/web"]
    )


def test_ecs_service_discovery_batches_describe_calls_by_ten():
    client = Mock()
    client.list_clusters.return_value = {"clusterArns": ["cluster"]}
    client.list_services.return_value = {"serviceArns": [f"service-{i}" for i in range(12)]}
    client.describe_services.side_effect = [
        {"services": [{"serviceArn": f"service-{i}"} for i in range(10)]},
        {"services": [{"serviceArn": "service-10"}, {"serviceArn": "service-11"}]},
    ]
    resources = AWSProvider(ecs_client=client).discover_ecs_services()
    assert len(resources) == 12
    assert [len(call.kwargs["services"]) for call in client.describe_services.call_args_list] == [10, 2]
