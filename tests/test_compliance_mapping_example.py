import json
from pathlib import Path

from aws_security_scanner.compliance import load_mapping_file
from aws_security_scanner.rules.registry import get_all_rules


def test_cis_mapping_example_validates_against_registered_rules():
    repo_root = Path(__file__).resolve().parents[1]
    mapping_path = repo_root / "examples" / "compliance" / "cis-aws-foundations-benchmark-1.4.0.json"
    registered_ids = {rule.metadata.check_id for rule in get_all_rules()}

    mapping = load_mapping_file(mapping_path, registered_ids)

    assert mapping["framework"] == {
        "name": "CIS AWS Foundations Benchmark",
        "version": "1.4.0",
        "source_url": "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html",
    }
    assert len(mapping["controls"]) >= 8
    assert all(control["rationale"] for control in mapping["controls"])
    assert {check_id for control in mapping["controls"] for check_id in control["check_ids"]} <= registered_ids
