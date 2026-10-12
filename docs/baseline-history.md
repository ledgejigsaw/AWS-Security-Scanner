# Finding baselines, diffs and suppression governance

The scanner's baseline files are local JSON artifacts. They contain finding identity and selected finding metadata only; they must not contain credentials, secret values, or raw cloud configuration.

## Create a baseline

```bash
aws-security-scan --source terraform --file terraform.json --write-baseline reports/baseline.json
```

Newly written baselines use schema version 2 and store a sorted list of finding records. Version 1 files containing a `fingerprints` list remain readable. The identity is derived from check ID, service, resource identifier and region; evidence text, severity and title are not identity fields.

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
