# Security rule coverage matrix

This page describes the service-level coverage currently registered in `rules/registry.py`. It is a baseline inventory, not a statement of full AWS service coverage or compliance.

Terraform inputs may be supplied as Terraform JSON or direct HCL. HCL support is intentionally partial: the scanner does not evaluate variables, locals, `count`/`for_each`, dynamic blocks or module source. Such expressions/modules are surfaced as informational diagnostics.

## Current registered baseline

| Service/domain | Registered checks | Scope and important limitations |
|---|---:|---|
| S3 | 17 | Public exposure, encryption, versioning, Block Public Access, logging, selected bucket-policy risks, public ACL grants, ACL-based ownership, MFA Delete and lifecycle review signals, plus an informational cross-account bucket-policy grant check when owner-account identity is known and a policy-dependent Object Lock review signal for versioned buckets. Object Lock absence is not treated as universally insecure; account-level Block Public Access is checked separately from bucket-level settings. Conditions are recorded as context, not treated as proof that access is safe; no object-content inspection. |
| IAM | 17 | Permissions, trust, MFA, credential hygiene, root-account and unused-role signals. Not a complete IAM policy simulator. |
| EC2 | 12 | Public IPv4, metadata options, sensitive ports and broad ingress/egress. Detailed monitoring and missing instance-profile checks are informational review signals, not universal requirements. |
| EBS | 4 | Explicit unencrypted volume/snapshot states plus observed public snapshot create-volume and public AMI launch permissions. Permission-denied public-access checks remain unknown; approved cross-account sharing is not treated as public. |
| VPC/network | 10 | Subnets, routes and network ACL baselines. Not a complete reachability or network-path analyser. |
| CloudTrail | 5 | Trail logging, multi-region, log-file validation, CloudWatch Logs integration review and recent delivery errors. CloudWatch Logs absence is informational; it does not imply S3 delivery is broken. |
| Security Hub | 1 | Regional hub enablement; optional bounded native-finding import preserves source IDs and timestamps. Standards/control evaluation is not imported. |
| GuardDuty | 1 | Regional detector enablement; optional bounded native-finding import preserves source IDs and timestamps. |
| AWS Config | 3 | Regional recorder configuration, recording state and delivery-channel presence. Missing status remains unknown; API errors fail discovery. |
| Amazon Macie | 1 | Regional session enablement/paused status. This does not assess discovery-job coverage or delegated-administrator configuration; optional bounded native Macie finding import is available with `--include-native-findings`. |
| KMS | 4 | Rotation, pending deletion, wildcard key-policy access and unconditional cross-account access to sensitive KMS actions as a review signal. This is not a full IAM/KMS policy simulator. |
| RDS | 5 | Encryption, public accessibility, backup retention, deletion protection and reported server-certificate expiry within 30 days. Unknown certificate metadata is not flagged. |
| Lambda | 3 | Function URL authentication, wildcard invocation policies and a reviewed snapshot of known deprecated runtimes. Lifecycle data must be refreshed against AWS before release. |
| RDS | 4 | Encryption, public accessibility, backup retention and deletion protection. |
| Lambda | 4 | Function URL authentication, wildcard invocation policies and a reviewed snapshot of known deprecated runtimes. Lifecycle data must be refreshed against AWS before release. |
| Secrets Manager | 2 | Explicitly disabled rotation and unconditional wildcard-principal resource policies. Secret values must never be retrieved. |
| ECR | 2 | Mutable image tags and explicitly disabled scan-on-push. |
| DynamoDB | 3 | Point-in-time recovery, explicit server-side encryption state and deletion protection. |
| SQS | 2 | Sensitive wildcard access and explicit encryption state. Queue messages are never read. |
| SNS | 2 | Sensitive wildcard access and explicit encryption state. Messages are never published or consumed. |
| API Gateway REST APIs | 2 | Method authorization and stage access logging. HTTP APIs v2 are not yet covered. |
| WAFv2 | 2 | Managed rule group and rate-based rule coverage review signals; does not evaluate rule efficacy or managed-rule versions. |
| Application Load Balancers | 1 | Missing WAF association as an informational review signal. Network Load Balancers are not included. | 
| ECS/Fargate | 6 | Privileged mode, host networking, explicit root user, writable root filesystem, public-IP assignment and shared task/execution role review signal. Public IP assignment does not prove internet reachability; role sharing is informational. |
| CloudFront | 4 | Viewer HTTP allowance, explicitly weak minimum TLS policy, explicitly disabled access logging and absent WAF association as an informational review signal. No origin requests are made; S3 origin access is recorded but not yet evaluated. |
| **Total** | **110** | Includes Security Hub, GuardDuty, AWS Config and Amazon Macie posture checks. The registry contract tests validate unique IDs and metadata; re-run registry and CI checks when rules change. |

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
