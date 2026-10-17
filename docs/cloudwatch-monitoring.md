# CloudWatch log retention and monitoring review

The scanner discovers CloudWatch Logs log-group metadata and CloudWatch metric-alarm configuration through read-only APIs. It does not read log events, retrieve log messages or change alarm settings.

## Checks

- **CW-001 (LOW):** a log group has no explicit retention period. Retention is policy-dependent; the finding is a review signal, not a universal claim that every log group requires the same retention.
- **CW-002 (INFO):** a metric alarm has actions disabled or no alarm action target. Some alarms are intentionally informational, so this does not prove monitoring is ineffective.

The provider records log-group retention, KMS key metadata and alarm configuration. It does not yet correlate log metric filters to the full set of CIS security-alarm requirements. A future increment should implement explicitly scoped, evidence-backed control checks rather than assuming that generic alarm counts prove detection coverage.

## Permissions

The discovery paths use `logs:DescribeLogGroups` and `cloudwatch:DescribeAlarms`. Use a read-only audit role and treat access-denied or incomplete discovery as an assessment gap.

Run a scoped scan with:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service cloudwatch --format json --output reports/cloudwatch.json
```

All automated tests use mocked responses; live AWS validation has not been performed.
