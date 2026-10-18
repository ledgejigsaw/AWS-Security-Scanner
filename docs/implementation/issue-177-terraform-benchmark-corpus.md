# Issue #177 — Representative Terraform benchmark corpus

Status: implementation plan / draft PR. This document does not claim a representative differential benchmark has been implemented.

## Implementation sequence
1. Extend the existing offline synthetic corpus before importing public projects.
2. For every upstream fixture, pin repository URL and commit, record licence, local modifications, expected findings, and expected unresolved diagnostics.
3. Add secure, insecure, and ambiguous examples across the services named in issue #177, including multi-file roots and module relationships.
4. Normalise rule IDs, severities, source attribution, resource addresses, and diagnostics for deterministic comparison.
5. Add optional Checkov/Trivy adapters only when tools are installed; record exact versions/configuration and never claim equivalence without measured results.
6. Report true positives, false positives, false negatives, and unresolved coverage separately.

## Required tests
Offline deterministic run; pinned metadata validation; unexpected finding/severity/source changes fail CI; unknown diagnostics are not counted as passes; optional external tools are skipped cleanly.

## Licensing
Do not copy upstream code or fixtures until their licence and attribution requirements have been reviewed.