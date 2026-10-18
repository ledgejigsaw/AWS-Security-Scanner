# Issue #188 — IAM policy-context analysis

Status: implementation plan / draft PR. This document does not claim effective permissions are calculated.

## Implementation sequence
1. Extend inventory for attached and inline policies on users, groups, and roles, with policy-version handling.
2. Capture permissions-boundary presence and policy, trust-policy principals and conditions, and explicit denies.
3. Add Organizations SCP context only when available and authorised; represent unavailable context as unknown.
4. Collect supported resource-policy context without storing unnecessary raw policy payloads in reports.
5. Keep direct statement analysis separate from effective-authorization conclusions; do not claim effective access without complete documented evaluation semantics.

## Required tests
Attached/inline policies, default and non-default versions, boundaries, trust conditions, wildcard principals, explicit deny, AccessDenied, missing Organizations permissions, unavailable resource policies.

## Safety
Document least-privilege read-only actions, minimise sensitive evidence, and use fixtures/mocks in CI.