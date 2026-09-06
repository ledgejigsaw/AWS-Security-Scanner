from pathlib import Path

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.rules.s3_rules import (
    check_block_public_access,
    check_bucket_policy,
    check_wildcard_bucket_policy,
    check_public_bucket,
    check_encryption,
    check_versioning,
    check_logging,
)


FIXTURE_DIRECTORY = Path("tests/fixtures/s3")


def test_public_bucket_is_critical():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-sensitive-data"
    )

    findings = check_public_bucket(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_private_bucket_has_no_findings():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-secure-data"
    )

    findings = check_public_bucket(resource)

    assert findings == []

def test_unencrypted_bucket_generates_high_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-sensitive-data"
    )

    findings = check_encryption(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-002"
    assert findings[0].severity == Severity.HIGH

def test_encrypted_bucket_has_no_encryption_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-secure-data"
    )

    findings = check_encryption(resource)

    assert findings == []

def test_versioning_disabled_generates_medium_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-sensitive-data"
    )

    findings = check_versioning(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-003"
    assert findings[0].severity == Severity.MEDIUM

def test_versioning_enabled_has_no_versioning_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-secure-data"
    )

    findings = check_versioning(resource)

    assert findings == []

def test_logging_disabled_generates_medium_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-sensitive-data"
    )

    findings = check_logging(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-005"
    assert findings[0].severity == Severity.MEDIUM

def test_logging_enabled_has_no_logging_finding():
    provider = FixtureProvider(FIXTURE_DIRECTORY)
    resources = provider.discover()

    resource = next(
        resource
        for resource in resources
        if resource.resource_id == "company-secure-data"
    )

    findings = check_logging(resource)

    assert findings == []

def test_block_public_access_disabled_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "region": "eu-west-2",
            "public": True,
            "encryption": False,
            "versioning": False,
            "logging": False,
            "block_public_access": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_block_public_access(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-004"
    assert findings[0].severity == Severity.HIGH


def test_block_public_access_enabled_has_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-secure-data",
        attributes={
            "bucket_name": "company-secure-data",
            "region": "eu-west-2",
            "public": False,
            "encryption": True,
            "versioning": True,
            "logging": True,
            "block_public_access": True,
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_block_public_access(resource)

    assert findings == []

def test_public_bucket_policy_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "region": "eu-west-2",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-sensitive-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH


def test_restricted_bucket_policy_has_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-secure-data",
        attributes={
            "bucket_name": "company-secure-data",
            "region": "eu-west-2",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::123456789012:root"
                        },
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-secure-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_bucket_policy(resource)

    assert findings == []

def test_single_bucket_policy_statement_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "region": "eu-west-2",
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::company-sensitive-data/*",
                },
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH

def test_bucket_policy_with_wildcard_aws_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-sensitive-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_wildcard_federated_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "*"
                        },
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-sensitive-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH


def test_bucket_policy_with_wildcard_service_principal_generates_high_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "*"
                        },
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-sensitive-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-006"
    assert findings[0].severity == Severity.HIGH

def test_bucket_policy_with_deny_wildcard_principal_has_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-secure-data",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::company-secure-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_bucket_policy(resource)

    assert findings == []

def test_bucket_policy_with_specific_service_principal_has_no_finding():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-secure-data",
        attributes={
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "logging.s3.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::company-secure-data/*",
                    }
                ],
            },
        },
        source="fixture",
        region="eu-west-2",
    )

    findings = check_wildcard_bucket_policy(resource)

    assert findings == []