from pathlib import Path

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import (
    aggregate_s3_resources,
)
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.rules.registry import get_all_rules

def test_rule_engine_scans_terraform_resources():
    fixture = Path("tests/fixtures/terraform/s3_buckets.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    engine = RuleEngine(get_all_rules())
    findings = engine.scan(resources)

    terraform_findings = [
        finding
        for finding in findings
        if finding.resource == "insecure_bucket"
    ]

    assert len(terraform_findings) == 5

    check_ids = {
        finding.check_id
        for finding in terraform_findings
    }

    assert check_ids == {
        "S3-001",
        "S3-002",
        "S3-003",
        "S3-004",
        "S3-005",
    }

    secure_findings = [
        finding
        for finding in findings
        if finding.resource == "secure_bucket"
    ]

    assert secure_findings == []

def test_rule_engine_detects_terraform_s3_bucket_policy():
    fixture = Path("tests/fixtures/terraform/realistic_s3.json")

    provider = TerraformProvider(fixture)
    resources = provider.discover()

    resources = aggregate_s3_resources(resources)

    engine = RuleEngine(get_all_rules())
    findings = engine.scan(resources)

    policy_findings = [
        finding
        for finding in findings
        if finding.check_id == "S3-006"
    ]

    assert len(policy_findings) == 1

    assert policy_findings[0].severity.value == "HIGH"
    assert policy_findings[0].service == "S3"
    assert policy_findings[0].resource == "company_data"