# Issue #177 — Representative Terraform benchmark corpus

## Implemented in this PR

- Added deterministic validation for imported-source metadata: repository URL,
  full 40-character commit SHA, licence identifier, local fixture path, and
  SHA-256 digest.
- Added Checkov and Trivy JSON normalizers retaining tool ID, severity,
  resource address, source file, and title without pretending their rule IDs
  are equivalent to this scanner's rule IDs.
- Added optional command adapters for installed Checkov or Trivy. The adapters
  never install dependencies, use a timeout, return a safe diagnostic when a
  tool is missing or fails, and do not include raw stderr in results.
- Added offline tests for metadata validation, hashing, normalizers, missing
  tools, and invalid tool output.

## Benchmark interpretation

External scanner results are normalized for comparison but are not automatically
counted as true positives or false positives against this scanner. Cross-tool
rule mappings need explicit review and must preserve severity and resource
address. The existing offline expected-finding evaluator remains the scoring
authority for labelled cases.

## Remaining limitation

This PR adds provenance and adapter infrastructure; it does not import public
Terraform repositories. Before importing any upstream fixture, review its
licence, pin the exact commit, record local modifications, and record a digest.
Synthetic fixtures remain valuable for deterministic offline regression tests.

## Validation

Tests were added but not executed in this editing session. CI and the local
pytest suite are required before merge.
