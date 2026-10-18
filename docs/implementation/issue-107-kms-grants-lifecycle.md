# Issue #107 — KMS grants and lifecycle review

## Changes

- KMS grant inventory now exposes a grant count, number of pages read, and an explicit pagination-completeness value.
- Access-denied, malformed, repeated-marker, and page-limit cases remain unknown; partial grant data is discarded rather than presented as a complete inventory.
- KMS-002 now covers both PendingDeletion and Disabled key states while preserving its stable check ID. Evidence records the actual state.
- KMS-005 remains a conservative review signal for grants containing CreateGrant or wildcard operations. A grant is not considered unsafe merely because it exists.

No key material or encrypted data is requested. The provider uses only read-only KMS APIs.

## Validation

Offline tests cover disabled-key lifecycle handling, grant discovery metadata, narrow grants, broad grants, pagination, and inaccessible grant metadata. CI must pass before merge; no live AWS account was used.
