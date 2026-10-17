from aws_security_scanner.providers.aws import AWSProvider


class FakeCodeBuild:
    def list_projects(self, **kwargs):
        if "nextToken" not in kwargs:
            return {"projects": ["demo"], "nextToken": "next"}
        return {"projects": ["second"]}

    def batch_get_projects(self, *, names):
        return {
            "projects": [
                {
                    "name": name,
                    "arn": f"arn:aws:codebuild:eu-west-2:111111111111:project/{name}",
                    "serviceRole": "arn:aws:iam::111111111111:role/build-role",
                    "environment": {
                        "type": "LINUX_CONTAINER",
                        "image": "aws/codebuild/standard:7.0",
                        "computeType": "BUILD_GENERAL1_SMALL",
                        "privilegedMode": True,
                        "environmentVariables": [
                            {"name": "API_TOKEN", "value": "do-not-copy-secret", "type": "PLAINTEXT"},
                            {"name": "DB_PASSWORD", "value": "also-secret", "type": "SECRETS_MANAGER"},
                        ],
                    },
                    "source": {"type": "GITHUB", "location": "https://example.invalid/repo"},
                    "timeoutInMinutes": 30,
                    "vpcConfig": {"vpcId": "vpc-123", "subnets": ["subnet-123"], "securityGroupIds": ["sg-123"]},
                    "logsConfig": {"cloudWatchLogs": {"status": "ENABLED", "groupName": "/codebuild/demo"}},
                }
                for name in names
            ]
        }


def test_codebuild_discovery_paginates_and_never_stores_environment_values():
    provider = object.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.codebuild_client = FakeCodeBuild()

    resources = provider.discover_codebuild_projects()

    assert {item.resource_id for item in resources} == {"demo", "second"}
    project = next(item for item in resources if item.resource_id == "demo")
    assert project.attributes["privileged_mode"] is True
    assert project.attributes["environment_variables"] == [
        {"name": "API_TOKEN", "type": "PLAINTEXT"},
        {"name": "DB_PASSWORD", "type": "SECRETS_MANAGER"},
    ]
    assert "do-not-copy-secret" not in repr(project.attributes)
    assert "also-secret" not in repr(project.attributes)
    assert project.attributes["cloudwatch_logs_status"] == "ENABLED"
