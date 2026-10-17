from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.s3_rules import check_lifecycle_configuration_review
from aws_security_scanner.models.rule import Severity


def _bucket(attributes):
    return Resource(
        resource_type="aws_s3_bucket",
        resource_id="example-bucket",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_lifecycle_review_flags_known_absence_for_non_versioned_bucket():
    findings = check_lifecycle_configuration_review(
        _bucket({
            "lifecycle_configuration": {"status": "NOT_CONFIGURED", "rules": []},
            "versioning_configuration": {"status": "Suspended"},
        })
    )

    assert len(findings) == 1
    assert findings[0].check_id == "S3-018"
    assert findings[0].severity == Severity.INFO
    assert "NOT_CONFIGURED" in findings[0].evidence


def test_lifecycle_review_does_not_duplicate_versioned_bucket_signal():
    findings = check_lifecycle_configuration_review(
        _bucket({
            "lifecycle_configuration": {"status": "NOT_CONFIGURED", "rules": []},
            "versioning_configuration": {"status": "Enabled"},
        })
    )

    assert findings == []


def test_lifecycle_review_ignores_configured_or_unknown_state():
    for status in ("CONFIGURED", "UNKNOWN", None):
        findings = check_lifecycle_configuration_review(
            _bucket({
                "lifecycle_configuration": {"status": status, "rules": []},
                "versioning_configuration": {"status": "Suspended"},
            })
        )
        assert findings == []


def test_lifecycle_review_ignores_unobservable_configuration():
    assert check_lifecycle_configuration_review(_bucket({})) == []
