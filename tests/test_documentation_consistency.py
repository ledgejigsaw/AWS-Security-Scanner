import re
from pathlib import Path

from aws_security_scanner.rules.registry import get_all_rules


ROOT = Path(__file__).resolve().parents[1]


def test_readme_rule_count_matches_registered_rules():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"\*\*(\d+) registered security rules:\*\*", readme)

    assert match is not None, "README must state the registered rule count"
    assert int(match.group(1)) == len(get_all_rules())


def test_coverage_matrix_total_matches_registered_rules():
    matrix = (ROOT / "docs" / "rule-coverage.md").read_text(encoding="utf-8")
    match = re.search(r"\| \*\*Total\*\* \| \*\*(\d+)\*\* \|", matrix)

    assert match is not None, "Rule coverage matrix must state its total"
    assert int(match.group(1)) == len(get_all_rules())


def test_readme_does_not_claim_hcl_or_guardduty_ingestion_is_unimplemented():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "The direct HCL provider uses" in readme
    assert "Direct GuardDuty `GetFindings` ingestion is not yet implemented." not in readme
    assert "`config`" in readme
