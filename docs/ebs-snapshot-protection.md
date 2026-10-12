# EC2 and EBS data-protection checks

This feature adds metadata-only discovery for EBS volumes and snapshots owned by the current account in the selected region. It does not read volume blocks, snapshot contents, AMI contents, instance user data or application data.

## Checks

| ID | Default severity | Behaviour |
|---|---|---|
| EBS-001 | HIGH | Flags only volumes where AWS explicitly reports `Encrypted=false`. |
| EBS-002 | HIGH | Flags only snapshots where AWS explicitly reports `Encrypted=false`. |
| EBS-003 | CRITICAL | Flags only snapshots where the create-volume permission response explicitly contains `Group=all`. |
| EC2-011 | INFO | Review signal when detailed monitoring is explicitly disabled; detailed monitoring is not universally required. |
| EC2-012 | INFO | Review signal when no instance profile association is observed; instances do not universally need an instance role. |

Missing encryption or sharing fields are not treated as insecure. If the API denies access to a snapshot's create-volume permissions, public access remains unknown and no EBS-003 finding is emitted.

## Discovery and IAM permissions

The provider uses read-only EC2 APIs:
- `ec2:DescribeInstances`
- `ec2:DescribeVolumes`
- `ec2:DescribeSnapshots`
- `ec2:DescribeSnapshotAttribute`

Snapshot discovery is limited to snapshots owned by the caller's account (`OwnerIds=["self"]`). Calls use continuation-token pagination where the API supports it. `DescribeSnapshotAttribute` permission failures are preserved as unknown public-access state; other API errors are raised rather than silently treated as clean.

## Limitations

- AMI launch permissions and public AMI exposure are not yet assessed.
- Snapshot sharing with specific external accounts is not classified as public.
- Lifecycle, retention, Recycle Bin, Fast Snapshot Restore and EBS encryption-by-default settings are not assessed.
- Detailed monitoring and instance-profile absence are informational signals because the appropriate baseline depends on workload and organisation policy.
- Tests use mocks and synthetic metadata; this is not live-account validation.
