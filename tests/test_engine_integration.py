from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.registry import get_all_rules


def test_rule_engine_runs_registered_s3_rules():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="company-sensitive-data",
        attributes={
            "bucket_name": "company-sensitive-data",
            "public": True,
            "encryption": False,
            "versioning": False,
            "logging": False,
            "block_public_access": False,
        },
        source="fixture",
        region="eu-west-2",
    )

    engine = RuleEngine(get_all_rules())

    findings = engine.scan([resource])

    check_ids = {finding.check_id for finding in findings}

    assert "S3-001" in check_ids
    assert "S3-002" in check_ids
    assert "S3-003" in check_ids
    assert "S3-004" in check_ids
    assert "S3-005" in check_ids

from pathlib import Path

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.rules.registry import get_all_rules


def test_rule_engine_runs_registered_iam_rules():
    fixture_directory = Path("tests/fixtures/iam")

    provider = FixtureProvider(fixture_directory)
    resources = provider.discover()

    engine = RuleEngine(get_all_rules())
    findings = engine.scan(resources)

    iam_findings = [
        finding
        for finding in findings
        if finding.check_id == "IAM-001"
    ]

    assert len(iam_findings) == 1
    assert iam_findings[0].severity.value == "CRITICAL"
    assert iam_findings[0].service == "IAM"
    assert iam_findings[0].resource == "AdministratorLikePolicy"

def test_rule_engine_runs_registered_iam_003_rule():
    fixture_directory = Path("tests/fixtures/iam")

    provider = FixtureProvider(fixture_directory)
    resources = provider.discover()

    engine = RuleEngine(get_all_rules())
    findings = engine.scan(resources)

    iam_findings = [
        finding
        for finding in findings
        if finding.check_id == "IAM-003"
    ]

    assert len(iam_findings) == 1
    assert iam_findings[0].severity.value == "HIGH"
    assert iam_findings[0].service == "IAM"
    assert iam_findings[0].resource == "HighRiskAdminPolicy"

def test_rule_engine_runs_registered_iam_004_rule():
    fixture_directory = Path("tests/fixtures/iam")

    provider = FixtureProvider(fixture_directory)
    resources = provider.discover()

    engine = RuleEngine(get_all_rules())
    findings = engine.scan(resources)

    iam_findings = [
        finding
        for finding in findings
        if finding.check_id == "IAM-004"
    ]

    assert len(iam_findings) == 1
    assert iam_findings[0].severity.value == "HIGH"
    assert iam_findings[0].service == "IAM"
    assert iam_findings[0].resource == "PublicAssumableRole"