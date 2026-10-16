from unittest.mock import Mock

from botocore.exceptions import ClientError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.s3_rules import check_noncurrent_version_lifecycle
from aws_security_scanner.providers.aws import AWSProvider


def resource(versioning, lifecycle):
    return Resource(
        resource_type="aws_s3_bucket",
        resource_id="versioned-data",
        attributes={
            "versioning_configuration": versioning,
            "lifecycle_configuration": lifecycle,
        },
        source="aws",
        region="eu-west-2",
    )


def test_lifecycle_signal_only_applies_to_versioned_bucket_with_observable_config():
    finding = check_noncurrent_version_lifecycle(
        resource({"status": "Enabled"}, {"status": "NOT_CONFIGURED", "rules": []})
    )
    assert len(finding) == 1
    assert finding[0].check_id == "S3-014"
    assert finding[0].severity.value == "INFO"
    assert "No lifecycle configuration" in finding[0].evidence

    assert check_noncurrent_version_lifecycle(
        resource({"status": "Suspended"}, {"status": "NOT_CONFIGURED", "rules": []})
    ) == []
    assert check_noncurrent_version_lifecycle(
        resource({"status": "Enabled"}, {"status": "UNKNOWN", "rules": []})
    ) == []
    assert check_noncurrent_version_lifecycle(
        resource(None, {"status": "NOT_CONFIGURED", "rules": []})
    ) == []


def test_lifecycle_signal_not_emitted_when_enabled_noncurrent_expiration_exists():
    findings = check_noncurrent_version_lifecycle(
        resource(
            {"status": "Enabled"},
            {
                "status": "CONFIGURED",
                "rules": [
                    {
                        "status": "Enabled",
                        "has_noncurrent_version_expiration": True,
                    }
                ],
            },
        )
    )
    assert findings == []


def test_lifecycle_signal_emitted_when_configured_rules_do_not_expire_noncurrent_versions():
    findings = check_noncurrent_version_lifecycle(
        resource(
            {"status": "Enabled"},
            {
                "status": "CONFIGURED",
                "rules": [
                    {
                        "status": "Enabled",
                        "has_noncurrent_version_expiration": False,
                    }
                ],
            },
        )
    )
    assert len(findings) == 1
    assert "No enabled noncurrent-version expiration" in findings[0].evidence


def test_provider_distinguishes_missing_lifecycle_from_access_denied():
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = Mock()
    provider.s3_client.get_bucket_lifecycle_configuration.side_effect = ClientError(
        {"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "No lifecycle"}},
        "GetBucketLifecycleConfiguration",
    )
    assert provider._get_bucket_lifecycle_configuration("example") == {
        "status": "NOT_CONFIGURED",
        "rules": [],
    }

    provider.s3_client.get_bucket_lifecycle_configuration.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
        "GetBucketLifecycleConfiguration",
    )
    assert provider._get_bucket_lifecycle_configuration("example") == {
        "status": "UNKNOWN",
        "rules": [],
    }


def test_provider_normalises_noncurrent_lifecycle_rule():
    provider = AWSProvider.__new__(AWSProvider)
    provider.s3_client = Mock()
    provider.s3_client.get_bucket_lifecycle_configuration.return_value = {
        "Rules": [
            {
                "ID": "expire-old-versions",
                "Status": "Enabled",
                "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
            }
        ]
    }
    result = provider._get_bucket_lifecycle_configuration("example")
    assert result == {
        "status": "CONFIGURED",
        "rules": [
            {
                "id": "expire-old-versions",
                "status": "Enabled",
                "has_noncurrent_version_expiration": True,
                "has_expiration": False,
            }
        ],
    }


def test_terraform_s3_lifecycle_child_resource_is_aggregated_into_bucket():
    from aws_security_scanner.normalization.terraform import aggregate_s3_resources

    bucket = Resource(
        resource_type="aws_s3_bucket",
        resource_id="archive",
        attributes={},
        source="terraform",
    )
    lifecycle = Resource(
        resource_type="aws_s3_bucket_lifecycle_configuration",
        resource_id="archive_lifecycle",
        attributes={
            "rule": {
                "id": "expire-old",
                "status": "Enabled",
                "noncurrent_version_expiration": [{"noncurrent_days": 90}],
            }
        },
        source="terraform",
        relationships={"bucket": "aws_s3_bucket.archive"},
    )

    resources = aggregate_s3_resources([bucket, lifecycle])

    assert resources == [bucket]
    assert bucket.attributes["lifecycle_configuration"] == {
        "status": "CONFIGURED",
        "rules": [{
            "id": "expire-old",
            "status": "Enabled",
            "has_noncurrent_version_expiration": True,
        }],
    }
    assert check_noncurrent_version_lifecycle(
        resource({"status": "Enabled"}, bucket.attributes["lifecycle_configuration"])
    ) == []


def test_terraform_s3_object_lock_child_resource_is_aggregated_conservatively():
    from aws_security_scanner.normalization.terraform import aggregate_s3_resources

    bucket = Resource(
        resource_type="aws_s3_bucket",
        resource_id="records",
        attributes={},
        source="terraform",
    )
    object_lock = Resource(
        resource_type="aws_s3_bucket_object_lock_configuration",
        resource_id="records_lock",
        attributes={
            "object_lock_enabled": "Enabled",
            "rule": {"default_retention": [{"mode": "GOVERNANCE", "days": 30}]},
        },
        source="terraform",
        relationships={"bucket": "aws_s3_bucket.records"},
    )

    resources = aggregate_s3_resources([bucket, object_lock])

    assert resources == [bucket]
    assert bucket.attributes["object_lock_configuration"]["status"] == "CONFIGURED"
    assert bucket.attributes["object_lock_configuration"]["object_lock_enabled"] == "Enabled"


def test_terraform_s3_lifecycle_child_resource_without_matching_bucket_is_ignored():
    from aws_security_scanner.normalization.terraform import aggregate_s3_resources

    lifecycle = Resource(
        resource_type="aws_s3_bucket_lifecycle_configuration",
        resource_id="orphan_lifecycle",
        attributes={"rule": {"status": "Enabled"}},
        source="terraform",
        relationships={"bucket": "aws_s3_bucket.missing"},
    )
    assert aggregate_s3_resources([lifecycle]) == []
