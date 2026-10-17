# Resource inventory snapshots

Resource snapshots let you preserve the scanner's normalised resource inventory and replay it through the same rule engine without AWS credentials or network access.

## Create and replay a snapshot

Snapshot output is opt-in:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 \
  --service s3 --service iam \
  --snapshot-output reports/inventory.json \
  --format json --output reports/scan.json
```

Re-run the current rules against the saved inventory later:

```bash
aws-security-scan --source snapshot --file reports/inventory.json \
  --format sarif --output reports/reanalysis.sarif
```

The schema is versioned as `1.0.0`. It records the collection timestamp, source, region, normalised resource identities and attributes, relationships, IaC source context and discovery-coverage metadata. Replay preserves discovery gaps so an incomplete original collection is not silently presented as complete. Unsupported schema versions and unknown resource/root fields are rejected rather than dropped.

## Data handling

A snapshot can contain sensitive infrastructure metadata, resource names, IAM policy documents, network identifiers and account identifiers. Treat it as a security artifact: store it with appropriate access controls, avoid committing production snapshots, and define a retention policy. Snapshot export redacts common credential-like keys recursively; this is defence in depth, not a guarantee that every arbitrary custom field is non-sensitive. Review snapshots before sharing them.

The scanner does not retrieve secret values or log contents as part of this feature. The CodeBuild provider retains environment-variable names and types, not values.

Snapshots are immutable input artifacts for analysis; the scanner does not call AWS or apply changes during replay. A snapshot reflects the collection time and must not be treated as a current view of the cloud environment.
