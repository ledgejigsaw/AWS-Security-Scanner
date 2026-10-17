# Finding baselines, diffs and suppression governance

The scanner's baseline files are local JSON artifacts. They contain finding identity and selected finding metadata only; they must not contain credentials, secret values, or raw cloud configuration.

## Create a baseline

```bash
aws-security-scan --source terraform --file terraform.json --write-baseline reports/baseline.json
```

Newly written baselines currently use schema version 2 and store a sorted list of finding records. Version 1 files containing a `fingerprints` list remain readable. The identity is derived from check ID, service, resource identifier and region, with account ID included when available; evidence text, severity and title are not identity fields. JSON reports expose `schema_version` (`1.0.0`); SARIF retains its standard `2.1.0` format version and adds `scannerReportSchemaVersion` in run properties. These markers describe output structure, not the scanner's rule catalogue version.

## Compare against a previous baseline

```bash
aws-security-scan --source terraform --file terraform.json \
  --compare-baseline reports/baseline.json \
  --diff-output reports/baseline-diff.json
```

Diffs classify findings as `new`, `resolved`, or `unchanged`. Results are sorted by fingerprint for repeatable output. A changed evidence string alone does not create a new finding.

## Suppression metadata

Version 2 entries may include `suppression` metadata:

```json
{
  "reason": "Accepted temporary exception under risk review",
  "owner": "platform-security",
  "expires_on": "2027-03-31"
}
```

The reason is mandatory; owner and expiry are optional. Expiry must use ISO `YYYY-MM-DD`. An expired suppression is no longer active and therefore no longer suppresses the matching finding. Expiry dates are inclusive: a suppression remains active through its expiry date and becomes inactive the following day. Baseline membership and suppression are separate concepts: `--compare-baseline` never suppresses findings, and `--baseline` only filters findings with active baseline identities.

Version 1 fingerprints have no suppression metadata and retain legacy baseline-suppression behaviour. Keep baseline files under review, version them where appropriate, and review new findings before refreshing a baseline.


## Operational note

A baseline is a comparison reference, not proof that a resource is safe. Review newly introduced findings and any suppression expiry as part of normal change review; do not automatically rewrite the baseline in CI.


## Identity and compatibility

Finding fingerprints are deterministic hashes of identity metadata and exclude evidence text and other mutable display fields. Account identity is included when supplied, so callers should provide account context for multi-account scans. Older baselines remain loadable; because legacy entries may lack account identity, review baseline diffs carefully when migrating from scans that did not record accounts. Fingerprints must never include credentials, secret values, or raw resource configuration.
