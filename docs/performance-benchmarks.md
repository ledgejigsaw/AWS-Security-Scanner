# Performance and scale benchmarks

The benchmark harness measures the scanner's local processing stages independently:

- security-rule evaluation over normalised resources;
- resource graph generation;
- JSON report construction/serialisation size; and
- SARIF report construction/serialisation size.

It is intentionally an offline engineering tool, not a live AWS load test. It does not create AWS clients, resolve credentials, run Terraform, download modules, or make network requests. Synthetic resources are copied from a local Terraform JSON input so the benchmark retains realistic resource attributes while assigning each copy a distinct resource ID.

## Run it

From the repository root in an installed development environment:

```bash
python scripts/benchmark_scan.py \
  --input tests/fixtures/terraform/realistic_s3.json \
  --sizes 100 500 1000 \
  --output reports/performance-benchmark.json
```

Omit `--output` to print JSON to stdout. Use a different local Terraform JSON file to explore other supported resource types. Keep test fixtures non-sensitive; the report records timings, counts and serialised output sizes, not resource attributes.

## Interpreting results

- Run the same command several times on the same machine and compare medians; short runs are affected by interpreter warm-up and system load.
- Compare like-for-like Python versions, dependency versions, hardware and resource counts.
- Use the stage timings to identify likely bottlenecks before optimising.
- The resource graph implementation can become more expensive as relationships and findings increase; do not infer large-scale performance from a single small run.
- Benchmark timings are observations, not hard assertions in normal CI. Avoid wall-clock thresholds in unit tests because they are environment-dependent.
- This does not measure boto3 latency, AWS throttling, API pagination or concurrent account scans. Those require a separately controlled environment.

The output schema is versioned independently from scan-report schemas as `benchmark_schema_version: 1.0.0`. Breaking changes to the benchmark result structure should increment that version.
