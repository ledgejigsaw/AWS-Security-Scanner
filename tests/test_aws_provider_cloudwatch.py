from aws_security_scanner.providers.aws import AWSProvider


class FakeLogs:
    def describe_log_groups(self, **kwargs):
        if "nextToken" in kwargs:
            return {"logGroups": [{"logGroupName": "/app/retained", "retentionInDays": 90}]}
        return {
            "logGroups": [{"logGroupName": "/app/unbounded", "storedBytes": 1024}],
            "nextToken": "page-2",
        }


class FakeCloudWatch:
    def describe_alarms(self, **kwargs):
        return {
            "MetricAlarms": [
                {
                    "AlarmName": "alarm-with-actions",
                    "ActionsEnabled": True,
                    "AlarmActions": ["arn:aws:sns:eu-west-2:111111111111:alerts"],
                    "Namespace": "AWS/EC2",
                    "MetricName": "CPUUtilization",
                },
                {
                    "AlarmName": "alarm-no-actions",
                    "ActionsEnabled": False,
                    "AlarmActions": [],
                    "Namespace": "AWS/EC2",
                    "MetricName": "StatusCheckFailed",
                },
            ]
        }


def test_cloudwatch_log_group_discovery_paginates_and_does_not_read_events():
    provider = object.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.logs_client = FakeLogs()

    resources = provider.discover_cloudwatch_log_groups()

    assert {item.resource_id for item in resources} == {"/app/unbounded", "/app/retained"}
    unbounded = next(item for item in resources if item.resource_id == "/app/unbounded")
    retained = next(item for item in resources if item.resource_id == "/app/retained")
    assert unbounded.attributes["retention_in_days"] is None
    assert retained.attributes["retention_in_days"] == 90
    assert all(item.region == "eu-west-2" for item in resources)


def test_cloudwatch_alarm_discovery_preserves_action_configuration():
    provider = object.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.cloudwatch_client = FakeCloudWatch()

    resources = provider.discover_cloudwatch_alarms()

    assert len(resources) == 2
    by_name = {item.resource_id: item for item in resources}
    assert by_name["alarm-with-actions"].attributes["actions_enabled"] is True
    assert by_name["alarm-with-actions"].attributes["alarm_actions"]
    assert by_name["alarm-no-actions"].attributes["actions_enabled"] is False
