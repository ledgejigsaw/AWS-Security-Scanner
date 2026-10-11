from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.ecr_rules import (
    check_ecr_mutable_image_tags,
    check_ecr_scan_on_push_disabled,
)


def make_repository(**attributes):
    return Resource(
        resource_type="aws_ecr_repository",
        resource_id="payments",
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_mutable_image_tags_generate_high_finding():
    findings = check_ecr_mutable_image_tags(
        make_repository(image_tag_mutability="MUTABLE")
    )
    assert len(findings) == 1
    assert findings[0].check_id == "ECR-001"
    assert findings[0].severity == Severity.HIGH


def test_immutable_or_unknown_tag_mutability_is_not_flagged():
    assert check_ecr_mutable_image_tags(
        make_repository(image_tag_mutability="IMMUTABLE")
    ) == []
    assert check_ecr_mutable_image_tags(make_repository()) == []
    assert check_ecr_mutable_image_tags(
        make_repository(image_tag_mutability="IMMUTABLE_WITH_EXCLUSION")
    ) == []


def test_disabled_scan_on_push_generates_medium_finding():
    findings = check_ecr_scan_on_push_disabled(
        make_repository(scan_on_push=False)
    )
    assert len(findings) == 1
    assert findings[0].check_id == "ECR-002"
    assert findings[0].severity == Severity.MEDIUM


def test_enabled_or_unknown_scan_on_push_is_not_flagged():
    assert check_ecr_scan_on_push_disabled(make_repository(scan_on_push=True)) == []
    assert check_ecr_scan_on_push_disabled(make_repository()) == []
