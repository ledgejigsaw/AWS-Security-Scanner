# Terraform benchmark corpus

The repository includes a deterministic, offline HCL corpus under tests/fixtures/terraform-hcl-benchmark. It intentionally contains secure, insecure and unknown/incomplete examples.

Run it from a checkout:

    python scripts/benchmark_terraform_corpus.py

Write a machine-readable result:

    python scripts/benchmark_terraform_corpus.py --output reports/terraform-benchmark.json

The manifest is versioned and records each case's expected stable finding IDs, expected analysis status, classification and rationale. The runner compares exact unique check-ID sets and completeness status, returning a non-zero exit code if any case differs. This makes both false-negative regressions and accidental extra findings visible.

## Current corpus

- Public S3 bucket: expects S3-001.
- Explicitly configured secure S3 example: expects no finding from the selected rule set.
- Unresolved variable: expects IAC-HCL-001 and incomplete analysis.
- Remote module: expects IAC-HCL-002 and incomplete analysis; no network fetch occurs.

These are synthetic regression cases, not a representative measurement of all AWS/Terraform security. Add one case per security property with secure/insecure/unknown variants where applicable. Include the reason for every expected finding and keep fixtures free of secrets or real account identifiers.

## Differential comparison with upstream scanners

Prowler is primarily a live AWS CSPM tool; Checkov and Trivy have dedicated IaC workflows; ScoutSuite focuses on cloud posture inventory. A meaningful differential run must pin tool versions, use equivalent inputs and compare semantics rather than raw counts. The current harness establishes our own stable baseline only; it does not claim differential parity. Future adapters should record tool version, command, exit status, normalized findings, unsupported/skipped cases and source URL. A check should be counted as equivalent only after its detection logic and unknown-state behaviour are reviewed.
