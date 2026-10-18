# AWS read-only permissions preflight

Run an advisory preflight before a normal scan:

```bash
aws-security-scan --source aws --profile audit --region eu-west-2 --service s3 --service kms --aws-permissions-preflight --format json --output reports/audit.json
```

With no `--service` filters, the preflight probes each service selector supported by the current probe matrix. It validates STS caller identity and then invokes one bounded read-only listing/description API per service. The results are included in assessment metadata for JSON, HTML and SARIF reports. The scan continues even if a probe fails; use actual discovery coverage to determine whether the scan was complete.

## Probe matrix

| Selector | Representative API | IAM action (expected) |
|---|---|---|
| s3 | ListBuckets | s3:ListAllMyBuckets |
| iam | ListRoles | iam:ListRoles |
| ec2 / vpc | DescribeVpcs | ec2:DescribeVpcs |
| ebs | DescribeVolumes | ec2:DescribeVolumes |
| cloudtrail | DescribeTrails | cloudtrail:DescribeTrails |
| kms | ListKeys | kms:ListKeys |
| rds | DescribeDBInstances | rds:DescribeDBInstances |
| lambda | ListFunctions | lambda:ListFunctions |
| secretsmanager | ListSecrets | secretsmanager:ListSecrets |
| ecr | DescribeRepositories | ecr:DescribeRepositories |
| dynamodb | ListTables | dynamodb:ListTables |
| sqs / sns | ListQueues / ListTopics | sqs:ListQueues / sns:ListTopics |
| apigateway | GetRestApis | apigateway:GET |
| ecs | ListClusters | ecs:ListClusters |
| cloudfront | ListDistributions | cloudfront:ListDistributions |
| waf | ListWebACLs (REGIONAL) | wafv2:ListWebACLs |
| elb | DescribeLoadBalancers | elasticloadbalancing:DescribeLoadBalancers |
| securityhub | GetFindings | securityhub:GetFindings |
| guardduty | ListDetectors | guardduty:ListDetectors |
| config | DescribeConfigurationRecorders | config:DescribeConfigurationRecorders |
| macie | GetMacieSession | macie2:GetMacieSession |
| eks | ListClusters | eks:ListClusters |
| cloudwatch | DescribeLogGroups | logs:DescribeLogGroups |
| efs | DescribeFileSystems | elasticfilesystem:DescribeFileSystems |
| codebuild | ListProjects | codebuild:ListProjects |

## Interpretation and least privilege

- `success` means the representative call succeeded, not that every action required by that service's full discovery is allowed.
- `access_denied`, `throttled`, `disabled`, `unsupported` and `failed` are distinct outcomes. A disabled service or denied probe is not equivalent to zero findings.
- The listed actions are representative IAM permissions. Some scanners require additional read-only actions, including resource-specific detail APIs and optional native-finding integrations. Consult AWS service IAM documentation and the discovery coverage report before finalising a policy.
- Use a dedicated read-only audit role. Do not grant write/remediation actions for assessment. Do not put credentials in CLI arguments or repository files.
- No resources are created, changed or deleted. Live AWS validation is manual; CI uses mocks and needs no credentials.
