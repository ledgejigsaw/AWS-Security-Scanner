# AWS Backup discovery and recovery evidence

The `backup` AWS service selector performs read-only metadata discovery using AWS Backup APIs:

- backup vault inventory;
- backup plan inventory;
- protected-resource inventory, including service-provided last-backup/recovery-point metadata.

Example:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service backup --format html --output reports/backup.html
```

Required read permissions depend on the APIs returned by the installed boto3 service model. At minimum, review `backup:ListBackupVaults`, `backup:ListBackupPlans` and `backup:ListProtectedResources`. Permission denial and pagination failures must remain coverage failures, not be interpreted as an empty inventory.

The `BACKUP-001` check is deliberately conservative: it emits a medium-severity review finding only when a protected-resource inventory item exposes neither a last-backup timestamp nor a recovery-point ARN. It does not prove that a workload is unprotected, that a backup is fresh, or that recovery is possible. Confirm AWS Backup job history and test restores using an approved recovery exercise.

Existing RDS backup-retention, DynamoDB point-in-time recovery, EBS snapshot and S3 versioning checks remain service-specific signals. Their presence does not establish that a complete recovery objective is met. The scanner never reads application data and never starts, modifies or deletes backup jobs, vaults or recovery points.
