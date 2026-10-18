# Issue #189 — Opt-in live AWS integration tests

Status: implementation plan / draft PR. This document does not claim live-account tests have been added or executed.

## Implementation sequence
1. Add a separate live-test marker and explicit opt-in environment variable; tests skip clearly by default.
2. Require an expected AWS account ID and verify caller identity before any discovery call.
3. Use read-only credentials and pre-created, externally managed fixtures only. Tests must never create, modify, or delete AWS resources.
4. Version expected resources/findings and redact account-sensitive data from test output.
5. Document dedicated-account setup, least-privilege permissions, fixture ownership, cleanup by the fixture owner, and how to invoke tests.

## Required tests
No opt-in -> skip; wrong account -> refuse; identity failure -> refuse; read-only scan path; normal CI excludes live tests.

## Validation reporting
Clearly distinguish mocked tests from live AWS validation. Do not claim live validation until the suite has been run against the dedicated account.