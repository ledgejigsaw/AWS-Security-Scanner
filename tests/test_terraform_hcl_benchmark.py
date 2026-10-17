from scripts.benchmark_terraform_corpus import run_benchmark


def test_terraform_hcl_benchmark_corpus_matches_expected_findings():
    result = run_benchmark()

    assert result["schema_version"] == "1.0.0"
    assert result["case_count"] >= 4
    assert result["failed"] == 0, result
    assert result["passed"] == result["case_count"]


def test_benchmark_covers_insecure_secure_and_unknown_states():
    result = run_benchmark()
    classes = {item["class"] for item in result["results"]}
    assert {"insecure", "secure", "unknown"} <= classes
    assert any(item["observed_status"] == "incomplete" for item in result["results"])
