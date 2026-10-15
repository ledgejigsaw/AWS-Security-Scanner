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
