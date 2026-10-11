from unittest.mock import Mock, call

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def test_dynamodb_discovery_normalises_security_metadata():
    client = Mock()
    client.list_tables.return_value = {"TableNames": ["payments"]}
    client.describe_table.return_value = {
        "Table": {
            "TableName": "payments",
            "TableArn": "arn:aws:dynamodb:eu-west-2:123456789012:table/payments",
            "TableStatus": "ACTIVE",
            "SSEDescription": {
                "Status": "ENABLED",
                "SSEType": "KMS",
                "KMSMasterKeyArn": "arn:aws:kms:eu-west-2:123456789012:key/example",
            },
            "DeletionProtectionEnabled": True,
        }
    }
    client.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {
                "PointInTimeRecoveryStatus": "ENABLED"
            }
        }
    }

    resources = AWSProvider(
        dynamodb_client=client, region="eu-west-2"
    ).discover_dynamodb_tables()

    assert len(resources) == 1
    resource = resources[0]
    assert isinstance(resource, Resource)
    assert resource.resource_type == "aws_dynamodb_table"
    assert resource.resource_id == "payments"
    assert resource.attributes["point_in_time_recovery_status"] == "ENABLED"
    assert resource.attributes["sse_status"] == "ENABLED"
    assert resource.attributes["sse_type"] == "KMS"
    assert resource.attributes["kms_key_arn"].endswith("key/example")
    assert resource.attributes["deletion_protection_enabled"] is True
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"
    client.describe_table.assert_called_once_with(TableName="payments")
    client.describe_continuous_backups.assert_called_once_with(TableName="payments")


def test_dynamodb_discovery_paginates_table_names():
    client = Mock()
    client.list_tables.side_effect = [
        {"TableNames": ["first"], "LastEvaluatedTableName": "first"},
        {"TableNames": ["second"]},
    ]
    client.describe_table.return_value = {"Table": {"TableName": "stub"}}
    client.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {}
    }

    resources = AWSProvider(
        dynamodb_client=client, region="eu-west-2"
    ).discover_dynamodb_tables()

    assert [r.resource_id for r in resources] == ["first", "second"]
    assert client.list_tables.call_args_list == [
        call(), call(ExclusiveStartTableName="first")
    ]


def test_dynamodb_discovery_handles_no_tables_and_unknown_metadata():
    client = Mock()
    client.list_tables.return_value = {"TableNames": []}
    provider = AWSProvider(dynamodb_client=client)
    assert provider.discover_dynamodb_tables() == []
    client.describe_table.assert_not_called()
    client.describe_continuous_backups.assert_not_called()
