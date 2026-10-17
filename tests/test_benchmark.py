import pytest

from aws_security_scanner.benchmark import evaluate_benchmark_case, evaluate_benchmark_suite


def test_perfect_case_scores_expected_positive_and_negative_checks():
    result = evaluate_benchmark_case({"fixture_id": "bucket", "expected_findings": ["S3-001"], "prohibited_findings": ["S3-002"]}, ["S3-001"])
    assert result["counts"] == {"tp": 1, "fn": 0, "fp": 0, "tn": 1}


def test_missed_and_prohibited_findings_are_distinguished_from_extra_checks():
    result = evaluate_benchmark_case({"fixture_id": "iam", "expected_findings": ["IAM-001"], "prohibited_findings": ["IAM-009"]}, ["IAM-009", "OTHER-001"])
    assert result["counts"] == {"tp": 0, "fn": 1, "fp": 1, "tn": 0}
    assert result["unclassified_observed_check_ids"] == ["OTHER-001"]


def test_unresolved_check_ids_are_excluded_from_scoring_and_reported():
    result = evaluate_benchmark_case({"fixture_id": "partial", "expected_findings": ["S3-001"], "prohibited_findings": ["S3-002"], "unresolved_check_ids": ["S3-001"]}, ["S3-001"])
    assert result["counts"] == {"tp": 0, "fn": 0, "fp": 0, "tn": 1}
    assert result["unresolved_check_ids"] == ["S3-001"]


def test_suite_metrics_and_zero_denominators_are_safe():
    manifest = {"schema_version": "1.0", "cases": [{"fixture_id": "empty", "expected_findings": [], "prohibited_findings": []}]}
    result = evaluate_benchmark_suite(manifest, {"empty": []})
    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall"] is None
    assert result["metrics"]["f1"] is None


def test_duplicate_ids_and_overlapping_expectations_are_rejected():
    with pytest.raises(ValueError):
        evaluate_benchmark_case({"fixture_id": "bad", "expected_findings": ["S3-001"], "prohibited_findings": ["S3-001"]}, [])
    with pytest.raises(ValueError):
        evaluate_benchmark_suite({"schema_version": "1.0", "cases": [{"fixture_id": "x"}, {"fixture_id": "x"}]}, {})
