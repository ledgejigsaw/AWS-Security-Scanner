from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.ebs_rules import (
    check_ebs_snapshot_encryption,
    check_ebs_volume_encryption,
    check_public_ebs_snapshot,
)
from aws_security_scanner.rules.ec2_rules import (
    check_instance_detailed_monitoring_disabled,
    check_instance_without_profile,
)


def resource(resource_type, resource_id, **attributes):
    return Resource(
        resource_type=resource_type,
        resource_id=resource_id,
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_ebs_rules_only_flag_explicit_insecure_states():
    assert check_ebs_volume_encryption(resource("aws_ebs_volume", "vol-1", encrypted=False))[0].check_id == "EBS-001"
    assert check_ebs_volume_encryption(resource("aws_ebs_volume", "vol-1", encrypted=True)) == []
    assert check_ebs_volume_encryption(resource("aws_ebs_volume", "vol-1")) == []
    assert check_ebs_snapshot_encryption(resource("aws_ebs_snapshot", "snap-1", encrypted=False))[0].check_id == "EBS-002"
    assert check_ebs_snapshot_encryption(resource("aws_ebs_snapshot", "snap-1", encrypted=None)) == []
    assert check_public_ebs_snapshot(resource("aws_ebs_snapshot", "snap-1", public=True))[0].check_id == "EBS-003"
    assert check_public_ebs_snapshot(resource("aws_ebs_snapshot", "snap-1", public=False)) == []
    assert check_public_ebs_snapshot(resource("aws_ebs_snapshot", "snap-1", public=None)) == []


def test_ec2_optional_hardening_rules_are_review_signals():
    assert check_instance_detailed_monitoring_disabled(resource("aws_instance", "i-1", monitoring_state="disabled"))[0].check_id == "EC2-011"
    assert check_instance_detailed_monitoring_disabled(resource("aws_instance", "i-1", monitoring_state="enabled")) == []
    assert check_instance_detailed_monitoring_disabled(resource("aws_instance", "i-1")) == []
    assert check_instance_without_profile(resource("aws_instance", "i-1", instance_profile_arn=None))[0].check_id == "EC2-012"
    assert check_instance_without_profile(resource("aws_instance", "i-1", instance_profile_arn="arn:aws:iam::123456789012:instance-profile/app")) == []
    assert check_instance_without_profile(resource("aws_instance", "i-1")) == []


def test_provider_discovers_volumes_and_snapshots_and_preserves_unknown_permissions(monkeypatch):
    class EC2:
        def describe_volumes(self, **kwargs):
            return {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False, "KmsKeyId": None, "State": "in-use", "Attachments": [{"InstanceId": "i-1"}]}]}

        def describe_snapshots(self, **kwargs):
            assert kwargs["OwnerIds"] == ["self"]
            return {"Snapshots": [
                {"SnapshotId": "snap-public", "Encrypted": True, "State": "completed", "OwnerId": "123456789012"},
                {"SnapshotId": "snap-unknown", "Encrypted": False, "State": "completed", "OwnerId": "123456789012"},
            ]}

        def describe_snapshot_attribute(self, **kwargs):
            if kwargs["SnapshotId"] == "snap-public":
                return {"CreateVolumePermissions": [{"Group": "all"}]}
            raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "not permitted"}}, "DescribeSnapshotAttribute")

    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: object())
    provider = AWSProvider(ec2_client=EC2(), region="eu-west-2")
    volumes = provider.discover_ebs_volumes()
    snapshots = provider.discover_ebs_snapshots()
    assert volumes[0].attributes["encrypted"] is False
    assert volumes[0].attributes["attached_instance_ids"] == ["i-1"]
    assert snapshots[0].attributes["public"] is True
    assert snapshots[1].attributes["public"] is None
    assert snapshots[1].attributes["encrypted"] is False
