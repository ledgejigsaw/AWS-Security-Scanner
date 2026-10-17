from aws_security_scanner.providers.aws import AWSProvider


class FakeEFS:
    def describe_file_systems(self, **kwargs):
        return {
            "FileSystems": [{
                "FileSystemId": "fs-123",
                "Name": "shared-data",
                "FileSystemArn": "arn:aws:elasticfilesystem:eu-west-2:111111111111:file-system/fs-123",
                "Encrypted": False,
                "KmsKeyId": None,
                "PerformanceMode": "generalPurpose",
                "ThroughputMode": "bursting",
                "LifeCycleState": "available",
            }]
        }

    def describe_mount_targets(self, **kwargs):
        return {"MountTargets": [{
            "MountTargetId": "fsmt-123",
            "SubnetId": "subnet-123",
            "NetworkInterfaceId": "eni-123",
            "LifeCycleState": "available",
        }]}

    def describe_mount_target_security_groups(self, *, MountTargetId):
        assert MountTargetId == "fsmt-123"
        return {"SecurityGroups": ["sg-123"]}

    def describe_access_points(self, **kwargs):
        return {"AccessPoints": [{
            "AccessPointId": "fsap-123",
            "AccessPointArn": "arn:aws:elasticfilesystem:eu-west-2:111111111111:access-point/fsap-123",
            "PosixUser": {"Uid": 0, "Gid": 0},
            "RootDirectory": {"Path": "/app"},
            "LifeCycleState": "available",
        }]}


def test_efs_discovery_preserves_encryption_mount_target_and_access_point_metadata():
    provider = object.__new__(AWSProvider)
    provider.region = "eu-west-2"
    provider.efs_client = FakeEFS()

    resources = provider.discover_efs_file_systems()

    file_system = next(item for item in resources if item.resource_type == "aws_efs_file_system")
    access_point = next(item for item in resources if item.resource_type == "aws_efs_access_point")
    assert file_system.resource_id == "fs-123"
    assert file_system.attributes["encrypted"] is False
    assert file_system.attributes["mount_targets"][0]["security_group_ids"] == ["sg-123"]
    assert access_point.resource_id == "fsap-123"
    assert access_point.attributes["posix_user"]["Uid"] == 0
    assert all(item.region == "eu-west-2" for item in resources)
