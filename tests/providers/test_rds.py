from unittest.mock import Mock, call

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider


def test_rds_discovery_normalises_security_attributes():
    rds_client = Mock()
    rds_client.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "customer-db",
                "Engine": "postgres",
                "DBInstanceStatus": "available",
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "BackupRetentionPeriod": 0,
                "DeletionProtection": False,
                "MultiAZ": False,
                "Endpoint": {"Address": "customer-db.example.invalid"},
            }
        ]
    }

    provider = AWSProvider(rds_client=rds_client, region="eu-west-2")
    resources = provider.discover_rds_instances()

    assert len(resources) == 1
    resource = resources[0]
    assert isinstance(resource, Resource)
    assert resource.resource_type == "aws_db_instance"
    assert resource.resource_id == "customer-db"
    assert resource.source == "aws"
    assert resource.region == "eu-west-2"
    assert resource.attributes["storage_encrypted"] is False
    assert resource.attributes["publicly_accessible"] is True
    assert resource.attributes["backup_retention_period"] == 0
    assert resource.attributes["deletion_protection"] is False
    assert resource.attributes["engine"] == "postgres"


def test_rds_discovery_follows_marker_pagination():
    rds_client = Mock()
    rds_client.describe_db_instances.side_effect = [
        {
            "DBInstances": [{"DBInstanceIdentifier": "db-one"}],
            "Marker": "next-page",
        },
        {
            "DBInstances": [{"DBInstanceIdentifier": "db-two"}],
        },
    ]

    provider = AWSProvider(rds_client=rds_client, region="eu-west-2")
    resources = provider.discover_rds_instances()

    assert [resource.resource_id for resource in resources] == ["db-one", "db-two"]
    assert rds_client.describe_db_instances.call_args_list == [
        call(),
        call(Marker="next-page"),
    ]
