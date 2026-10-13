# Multi-account assessment foundations

Multi-account assessment is being developed in stages. This first foundation adds an optional AWS account identifier to normalised resources and findings, propagates it through the rule engine, and includes it in finding fingerprints and baseline records when present.

## Compatibility

Single-account and fixture scans that do not set an account ID retain their previous finding fingerprints. Account IDs are included in identity only when the scanner has explicitly identified the account. This prevents the same resource name in two accounts from collapsing into one finding while avoiding an unnecessary baseline migration for existing single-account users.

## Not implemented by this foundation

This change does not yet assume cross-account roles, enumerate AWS Organizations accounts, perform multi-account orchestration, or add account metadata to every report format. Those require follow-up work for role trust, expected-account validation, per-account scan status, partial failures and report-level metadata.

The planned first operational workflow is opt-in and sequential: accept explicit role targets, assume a least-privilege audit role with short-lived credentials, validate the resulting STS identity against the account expected from the role ARN, then report each target's status independently. Concurrency should follow only after sequential failure semantics are tested.
