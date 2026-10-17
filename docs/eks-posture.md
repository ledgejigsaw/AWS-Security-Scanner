# Amazon EKS posture checks

The EKS provider uses read-only EKS APIs to enumerate cluster names and describe cluster-level configuration. It does not enumerate workloads, execute commands in containers, read Kubernetes secrets, or change cluster settings.

## Checks

- **EKS-001 (HIGH):** public Kubernetes API endpoint allow-list includes `0.0.0.0/0` or `::/0`. A restricted public endpoint does not trigger this rule.
- **EKS-002 (MEDIUM):** EKS logging metadata is available but audit control-plane logging is not enabled. If logging metadata is unavailable, the rule does not infer that logging is disabled.
- **EKS-003 (INFO):** public endpoint access is enabled and private endpoint access is explicitly disabled. This is a review signal, not proof that an endpoint is reachable.

The provider retains endpoint access settings, public CIDRs, cluster security-group IDs, subnet IDs, enabled control-plane log types, encryption-configuration metadata, cluster version and status where returned. It does not currently perform full network reachability analysis or infer workload-level Kubernetes RBAC posture.

## Permissions and limitations

The minimum API operations for this discovery path are `eks:ListClusters` and `eks:DescribeCluster`. Use a read-only audit role and verify the effective permissions against the current AWS IAM documentation. Access-denied and regional failures should be treated as discovery gaps, not clean results.

Run a scoped scan with:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service eks --format json --output reports/eks.json
```

All automated tests use mocked responses; a live AWS account assessment has not yet been performed.
