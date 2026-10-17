# Amazon EFS posture checks

The scanner uses read-only EFS APIs to discover file-system metadata, mount-target metadata, associated security-group IDs and access-point POSIX configuration. It does not read file contents or infer internet reachability from security-group IDs alone.

## Checks

- **EFS-001 (MEDIUM):** the EFS API explicitly reports `Encrypted=false`. Missing encryption metadata is treated as unknown.
- **EFS-002 (INFO):** an access point explicitly maps clients to POSIX UID 0. This is a review signal, not proof of exploitable access.

The current provider records mount-target subnet and network-interface IDs plus security-group IDs, but it does not yet correlate those groups with full ingress rules or calculate NFS network reachability. The scanner must not label an EFS mount target publicly reachable based solely on its security-group association.

## Permissions

The discovery path uses EFS read-only operations including `elasticfilesystem:DescribeFileSystems`, `elasticfilesystem:DescribeMountTargets`, `elasticfilesystem:DescribeMountTargetSecurityGroups` and `elasticfilesystem:DescribeAccessPoints`. Confirm current IAM action names and resource-level support against AWS documentation before deploying a production audit policy.

Run a scoped scan with:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service efs --format json --output reports/efs.json
```

Tests use mocked API responses; live AWS validation has not been performed.
