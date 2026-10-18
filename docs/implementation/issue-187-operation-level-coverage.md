# Issue #187 — Operation-level discovery coverage

Status: implementation plan / draft PR. This document does not claim operation-level coverage is implemented.

## Implementation sequence
1. Define a typed discovery-operation result with service, operation, scope, outcome, count, pagination/completeness, safe error category, and permission mapping.
2. Keep a successful empty result distinct from access denied, disabled service, throttling, unsupported APIs, and unexpected failures.
3. Adapt existing provider discovery functions incrementally, preserving existing resource return contracts until callers migrate.
4. Emit deterministic, versioned machine-readable coverage and concise CLI summary.
5. Define when critical discovery gaps make the assessment incomplete and document exit-code semantics.

## Required tests
Successful empty results; paginated results; access denied; disabled services; throttling; partial failures; redaction of sensitive payloads; backward compatibility for report consumers.

## Safety
Use documented IAM actions where known and label uncertain mappings rather than guessing. Default CI remains offline.