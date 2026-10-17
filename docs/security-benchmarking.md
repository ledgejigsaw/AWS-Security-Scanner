# Reproducible security-scan benchmark

The `aws_security_scanner.benchmark` module scores observed check IDs against a versioned manifest. Each case declares `fixture_id`, `expected_findings`, `prohibited_findings`, and optional `unresolved_check_ids`. Expected IDs that are not observed count as false negatives; prohibited IDs that are observed count as false positives. Unclassified observed IDs are surfaced but are not counted as false positives until explicitly prohibited by the benchmark author.

`evaluate_benchmark_suite(manifest, observed_by_fixture)` returns deterministic per-case results and aggregate precision, recall, and F1. A metric is `null` when its denominator is zero rather than inventing a score. Unresolved check IDs are excluded from scoring and listed separately.

The starter manifest is `tests/fixtures/benchmarks/security-benchmark-v1.json`. Its expectations are scaffolding and must be checked against the referenced fixtures before making quality claims. A useful mature benchmark should include secure and insecure fixtures, edge cases, unsupported/unresolved cases, and independently reviewed expected results. Fixture performance is not a guarantee of accuracy against every live AWS account.

This API is offline and has no credentials or network requirements.
## Running the evaluator

Prepare an observed-results JSON file mapping each `fixture_id` to the check IDs returned by a scan, then run:

```bash
python scripts/evaluate_benchmarks.py \\
  --manifest tests/fixtures/benchmarks/security-benchmark-v1.json \\
  --observed reports/benchmark-observed.json \\
  --output reports/benchmark-results.json
```

The script evaluates recorded outputs; it does not itself execute scans or assume fixture expectations are correct. Run scans against each fixture using the scanner's normal fixture workflow and keep the observed file with the benchmark run for reproducibility.
