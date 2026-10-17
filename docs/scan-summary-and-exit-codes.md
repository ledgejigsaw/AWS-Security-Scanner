# Machine-readable scan summary and exit codes

The CLI can write a separate, versioned summary JSON document for CI jobs and downstream automation:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --format sarif \
  --output reports/scan.sarif \
  --summary-output reports/scan-summary.json \
  --fail-on HIGH
```

The normal JSON, HTML or SARIF report remains the detailed findings artifact. The summary is deliberately compact and contains the schema version, scan source/scope, duration, finding counts by severity, discovery completeness, multi-account success/failure counts when applicable, report destination and whether the configured failure threshold was met. It does not copy resource attributes, policies, credentials or secret values. For HCL scans, the summary also contains an analysis section with stable diagnostic counts for unresolved expressions, unexpanded modules and unevaluated data sources. Any of those diagnostics marks the assessment incomplete and produces exit code 1, even if no HIGH/CRITICAL finding was emitted. This prevents a partial static analysis from being mistaken for a clean result.

## Exit-code contract

| Code | Meaning |
|---:|---|
| `0` | Scan completed without a finding meeting `--fail-on`, or no threshold was configured. |
| `1` | Assessment was incomplete, a service discovery domain failed/was partial, an account failed, or a baseline operation was skipped to avoid treating partial results as resolved. |
| `2` | Invalid command-line input or configuration; argparse reports the reason. |
| `3` | Assessment completed, but one or more findings met the configured `--fail-on` severity threshold. |

Incomplete assessment takes precedence over the finding threshold: do not treat partial visibility as a passing result. Without `--fail-on`, findings alone do not change the exit code, preserving the existing default behaviour. `--min-severity` filters findings from the report; `--fail-on` evaluates the severity of the findings that remain after filtering.

The summary schema is versioned as `1.0.0`. Additive fields may be introduced compatibly; changes to field meaning or required structure should increment the schema version. The duration is observational and will vary between runs.
