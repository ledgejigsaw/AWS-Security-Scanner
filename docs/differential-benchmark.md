# Differential benchmark

Run the offline expected-outcome sample from the repository root:

```bash
python scripts/run_differential_benchmark.py
python scripts/run_differential_benchmark.py --output reports/differential-benchmark.json
```

The versioned manifest separates local regression expectations from upstream-tool equivalence. A passing case means the scanner matched the project's reviewed expected check IDs; it does **not** mean Prowler or Checkov parity. An `equivalent` mapping is rejected unless the upstream tool, check ID, version and rationale are supplied. The harness never installs or invokes upstream tools, makes no network requests, and does not require AWS credentials.

For each new mapping, record the exact upstream version and check ID, source URL, fixture provenance, expected semantics, exclusions and why the two checks are equivalent. Use `partial`, `not-equivalent`, `not-applicable` or `not-reviewed` where appropriate. Keep cloud-account comparisons as a separate opt-in procedure; never commit account exports, secrets or credentials.

The current manifest contains a small scanner regression sample and deliberately leaves upstream parity unreviewed. It is not a broad benchmark and must not be used as evidence of a false-negative rate or complete parity.
