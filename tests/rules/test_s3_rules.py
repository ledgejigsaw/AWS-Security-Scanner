from pathlib import Path

from aws_security_scanner.models.finding import Severity
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.rules.s3_rules import check_public_bucket


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