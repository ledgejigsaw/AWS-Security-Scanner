# Security rule coverage matrix

This page describes the service-level coverage currently registered in `rules/registry.py`. It is a baseline inventory, not a statement of full AWS service coverage or compliance.

## Current registered baseline

| Service/domain | Registered checks | Scope and important limitations |
|---|---:|---|
| S3 | 10 | Public exposure, encryption, versioning, Block Public Access, logging and selected bucket-policy risks. No object-content inspection. |
| IAM | 17 | Permissions, trust, MFA, credential hygiene, root-account and unused-role signals. Not a complete IAM policy simulator. |
| EC2 | 12 | Public IPv4, metadata options, sensitive ports and broad ingress/egress. Detailed monitoring and missing instance-profile checks are informational review signals, not universal requirements. |\n| EBS | 3 | Explicit unencrypted volume/snapshot states and observed public snapshot create-volume permissions. Permission-denied public-access checks remain unknown; AMI sharing and snapshot lifecycle are not covered. |
| VPC/network | 10 | Subnets, routes and network ACL baselines. Not a complete reachability or network-path analyser. |
| CloudTrail | 3 | Trail logging, multi-region and log-file validation baselines. Deeper account-wide coverage remains planned. |
| KMS | 3 | Rotation, pending deletion and wildcard key-policy access. |
| RDS | 4 | Encryption, public accessibility, backup retention and deletion protection. |
| Lambda | 3 | Function URL authentication, wildcard invocation policies and a reviewed snapshot of known deprecated runtimes. Lifecycle data must be refreshed against AWS before release. |
| Secrets Manager | 2 | Explicitly disabled rotation and unconditional wildcard-principal resource policies. Secret values must never be retrieved. |
| ECR | 2 | Mutable image tags and explicitly disabled scan-on-push. |
| DynamoDB | 3 | Point-in-time recovery, explicit server-side encryption state and deletion protection. |
| SQS | 2 | Sensitive wildcard access and explicit encryption state. Queue messages are never read. |
| SNS | 2 | Sensitive wildcard access and explicit encryption state. Messages are never published or consumed. |
| API Gateway REST APIs | 2 | Method authorization and stage access logging. HTTP APIs v2 are not yet covered. |
| ECS/Fargate | 6 | Privileged mode, host networking, explicit root user, writable root filesystem, public-IP assignment and shared task/execution role review signal. Public IP assignment does not prove internet reachability; role sharing is informational. |
| CloudFront | 4 | Viewer HTTP allowance, explicitly weak minimum TLS policy, explicitly disabled access logging and absent WAF association as an informational review signal. No origin requests are made; S3 origin access is recorded but not yet evaluated. |
| **Total** | **88** | Registry count for this branch including CloudFront and new EBS/EC2 checks; reconcile against `get_all_rules()` and CI before release. |

## Registry contract enforced by tests

The test suite now checks that:
- every registered rule has a non-empty, unique check ID;
- every registered rule has complete metadata for service, resource type, severity, category, title, description and remediation;
- the rule's declared resource type agrees with its metadata.

These checks prevent common registry errors, but they do not establish detection correctness or coverage completeness. Rule-specific tests must still cover confirmed insecure, safe and unknown/incomplete states.

## Updating this matrix

When a rule is added or removed:
1. Update the central registry.
2. Add rule and provider tests as appropriate.
3. Update the matrix and README counts in the same pull request.
4. Run the complete test suite and verify CI.
5. Review the matrix against the actual registry; do not rely on a hand-maintained count without checking it.
