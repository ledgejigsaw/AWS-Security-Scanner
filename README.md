# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources and Terraform JSON. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture and Terraform JSON scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS, API Gateway REST API stages, ECS task definitions and ECS services, and CloudFront distributions, regional and CloudFront-scope WAFv2 Web ACLs, and Application Load Balancers with WAF association metadata, plus regional Security Hub and GuardDuty posture discovery, with optional bounded import of native Security Hub findings. Live-account validation has not yet been completed.

## At a glance

- **100 registered security rules:** 14 S3, 17 IAM, 12 EC2, 3 EBS, 10 VPC/network, 5 CloudTrail, 1 Security Hub, 1 GuardDuty, 4 KMS, 4 RDS, 3 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway, 6 ECS, 4 CloudFront, 2 WAF and 1 Application Load Balancer check.
- **Test status:** CI runs the automated suite on Python 3.11 and 3.13; check the latest Actions run for the current branch status.
- **Inputs:** local JSON fixtures, Terraform JSON, Terraform HCL and AWS APIs.
- **Output:** JSON, self-contained HTML and SARIF 2.1.0 reporting, with minimum-severity filtering, versioned baseline comparison and expiry-aware suppression.
- **AWS access:** read-only API calls; tests use mocks and do not require AWS credentials.

Automated tests use mocks and fixtures; they do not replace validation against a real AWS account. Live scans remain unverified.

## Capabilities

### Sources

**Fixtures** provide deterministic, offline test inputs.

**Terraform JSON** can be generated from a plan/state representation with:

```bash
terraform show -json > terraform.json
```

The Terraform provider normalises resource data and resolves/aggregates related S3 resources, including bucket encryption, versioning, public-access-block, logging, lifecycle and bucket-policy configuration. Direct HCL parsing is not currently implemented.

**AWS APIs** are accessed through boto3 in read-only mode. Use `--profile` to select a profile from the standard AWS shared configuration/credentials files, and repeat `--service` to limit discovery to specific supported service domains. Without `--service`, the scanner runs its full supported discovery scope. For example:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service s3 --service iam --format json --output reports/s3-iam.json
```

Supported service selectors are `s3`, `iam`, `ec2`, `ebs`, `vpc`, `cloudtrail`, `kms`, `rds`, `lambda`, `secretsmanager`, `ecr`, `dynamodb`, `sqs`, `sns`, `apigateway`, `ecs`, `cloudfront`, `waf`, `elb`, `securityhub` and `guardduty`. These filters select discovery domains, not individual rule IDs. The profile name is not a credential and no credentials are accepted as command-line arguments. Profile and service options apply only to `--source aws`; the multi-account role-assumption mode uses the caller's default credential chain in this release.

The provider contains discovery methods for S3 buckets, IAM policies, roles, users and account-level credential-report settings, EC2 instances/security groups, EBS volumes and owned snapshots, VPCs, subnets, route tables, network ACLs, VPC flow logs, CloudTrail trails, KMS keys, RDS DB instances, Lambda functions, Secrets Manager secret metadata, ECR repositories, DynamoDB table metadata, SQS queue attributes, SNS topic attributes and API Gateway REST API stages, including method authorization metadata and stage access-log settings, plus ECS task-definition container settings and ECS service network configuration, and regional Security Hub hub status and GuardDuty detector status. Native Security Hub findings can be imported explicitly with `--include-native-findings`; GuardDuty findings are available through this integration only when surfaced by Security Hub. Direct GuardDuty `GetFindings` ingestion is not yet implemented. API discovery and rule coverage are not the same thing: some resource types have more comprehensive checks than others. A live AWS account has not yet been used for end-to-end validation. Secrets Manager discovery reads metadata and resource policies only; it never retrieves secret values.

WAF/application-edge discovery additionally covers regional and CloudFront-scope WAFv2 Web ACL metadata and Application Load Balancer WAF association state. See [WAF and application-edge posture](docs/waf-application-edge.md) for scope and limitations.

### Security checks

| Service | Coverage |
| --- | --- |
| S3 | Public exposure, encryption, versioning, Block Public Access, server-access logging, bucket-policy risks, public ACL grants, ACL-based ownership and MFA Delete review signals |
| IAM | Unrestricted and broad permissions, high-risk administrative actions, role trust policies, MFA, access-key state/age/inactivity, password/console credential hygiene and unused roles |
| EC2 | SSH/RDP and sensitive-port exposure, broad ingress/egress, public IPv4, IMDSv1 and broad IPv6 rules; detailed monitoring and missing instance-profile checks are informational review signals |
| EBS | Explicitly unencrypted volumes/snapshots and snapshots with an observed public create-volume permission; denied permission discovery remains unknown |
| VPC/network | Public subnet configuration, internet routes, broad IPv4/IPv6 routes, network ACL ingress/egress and default NACL checks |
| CloudTrail | Trail logging status, multi-region coverage, log-file validation, CloudWatch Logs integration review and recent delivery errors |
| Security Hub | Regional hub enablement posture; optional import of up to 100 native findings by default (limit configurable to 1,000), preserving source IDs, product ARNs and observation timestamps |
| GuardDuty | Regional detector enablement posture only; native findings and threat data are not imported |
| KMS | Automatic rotation, pending deletion, broad wildcard key-policy access and unconditional cross-account access to sensitive KMS actions as a review signal |
| RDS | Storage encryption, public accessibility, automated-backup retention and deletion protection |
| Lambda | Function URLs configured with unauthenticated access, unconditional wildcard-principal invocation policies and runtimes explicitly listed as deprecated in the reviewed AWS lifecycle snapshot |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |
| API Gateway (REST APIs) | Methods configured with no authorization when no API resource policy is present; stage access logging not configured |
| WAFv2 | Managed rule group and rate-based rule coverage review signals; CloudFront-scope ACLs use the global WAF endpoint in us-east-1 |
| Application Load Balancers | Missing WAF association as an informational review signal; network load balancers are not included | 
| ECS / Fargate | Privileged containers, host network mode, explicitly configured root users, writable container root filesystems and services assigning public IP addresses |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains 99 rules (13 S3, 17 IAM, 12 EC2, 3 EBS, 10 VPC/network, 5 CloudTrail, 1 Security Hub, 1 GuardDuty, 4 KMS, 4 RDS, 3 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway, 6 ECS, 4 CloudFront, 2 WAF and 1 Application Load Balancer). Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

### Policy and reporting

YAML policy files can enable/disable individual checks and override their severity. JSON reports include a summary and structured findings with check ID, severity, resource, description, remediation, region and evidence where available. An optional versioned compliance mapping file annotates JSON, HTML and SARIF reports with framework/version, control references, mapping confidence and rationale; mappings do not establish compliance. HTML reports provide a self-contained table for human review. SARIF 2.1.0 output maps scanner severities to SARIF levels and includes resource/evidence metadata for code-scanning ingestion.

Example fixture/Terraform scan:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --format json \
  --output reports/scan.json
```

Apply a custom policy:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --policy policies/default.yaml \
  --format json \
  --output reports/scan.json
```

Filter a scan to HIGH and CRITICAL findings:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --min-severity HIGH
```

Severity filtering is applied after policy overrides, so it uses each finding's effective severity. Valid thresholds are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` and `INFO`.

Create a baseline of the current findings:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --write-baseline reports/baseline.json
```

On later scans, suppress findings that match that baseline:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --baseline reports/baseline.json \
  --min-severity HIGH
```

New baseline files use schema version 2 and retain selected finding metadata, not raw configuration or secret values. Version 1 fingerprint-only files remain readable. Finding identity is derived from check ID, service, resource and region; changing evidence text does not create a new finding identity. A baseline suppresses matching findings from the report—it does not disable checks or alter the underlying rules. Version 2 entries can carry suppression reason, owner and ISO expiry date; expired suppressions stop suppressing. See [baseline history and suppression governance](docs/baseline-history.md) for semantics and examples.

Compare current results with a previous baseline without suppressing findings:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --compare-baseline reports/baseline.json \
  --diff-output reports/baseline-diff.json
```

The diff deterministically separates `new`, `resolved` and `unchanged` findings. `--diff-output` requires `--compare-baseline`; its default is `reports/baseline-diff.json`. The baseline-writing and suppression options remain mutually exclusive.

Generate SARIF for CI/code-scanning ingestion:

```bash
aws-security-scan \
  --source terraform \
  --file tests/fixtures/terraform/realistic_s3.json \
  --format sarif \
  --output reports/scan.sarif
```

Generate an HTML report with `--format html` (the default output is `reports/scan.html`). JSON remains the default format and writes to `reports/scan.json` unless `--output` is specified.

Run a read-only AWS scan (requires credentials with the necessary read permissions):

```bash
aws-security-scan --source aws --region eu-west-2 --format json --output reports/aws-scan.json
```

Opt in to import native AWS Security Hub findings from the selected region:

```bash
aws-security-scan --source aws --region eu-west-2 --include-native-findings --native-findings-limit 100 --format json --output reports/aws-scan-with-native-findings.json
```

### Opt-in multi-account assessment

Prepare an explicit JSON target list; each role ARN must belong to its declared account:

```json
{
  "accounts": [
    {
      "account_id": "123456789012",
      "role_arn": "arn:aws:iam::123456789012:role/SecurityAudit",
      "external_id": "optional-third-party-external-id"
    }
  ]
}
```

Run sequentially through the configured cross-account audit roles:

```bash
aws-security-scan --source aws --accounts-file accounts.json --region eu-west-2 --format json --output reports/multi-account-scan.json
```

The caller's credential chain must be allowed to call STS `AssumeRole`; each target role trust policy must trust that caller and grant the documented read-only discovery permissions. The scanner validates the assumed account with STS `GetCallerIdentity` before scanning and keeps short-lived credentials in memory only. Account lists are capped at 100, scans are sequential, and no Organizations-wide discovery is required. The JSON, HTML and SARIF report includes per-account success/failure and error details. If any account fails, the CLI exits non-zero after writing the report. Baseline write/compare/suppression is skipped on partial multi-account scans so an inaccessible account is not misreported as resolved.

Native finding import is disabled by default. It queries Security Hub and GuardDuty in the selected region and requires `securityhub:GetFindings`, `guardduty:ListDetectors`, `guardduty:ListFindings` and `guardduty:GetFindings`. The default cap is 100 findings per source; the supported limit is 1–1,000 per source. The scanner follows pagination up to each cap, deduplicates repeated source IDs, and lets API errors propagate rather than reporting an empty result. GuardDuty-backed Security Hub products are excluded from the Security Hub import when direct GuardDuty ingestion is enabled to avoid importing the same product through both APIs. Imported entries use `AWS-SHUB-NATIVE` or `AWS-GD-NATIVE` and preserve source type, source finding ID, account ID and observation timestamps where available. JSON, HTML and SARIF distinguish native findings from scanner-generated checks. Native source identity is included in baseline fingerprints so multiple findings on one resource do not collapse together.

Do not commit credentials, account exports containing sensitive data, or generated reports. Use a least-privilege read-only identity and validate required IAM permissions before scanning a production account.

## Container usage

Build the image locally:

```bash
docker build --pull -t aws-security-scanner:local .
```

Run a Terraform JSON scan with the input mounted read-only:

```bash
docker run --rm \
  --volume "$PWD/tests/fixtures/terraform:/fixtures:ro" \
  aws-security-scanner:local \
  --source terraform \
  --file /fixtures/realistic_s3.json \
  --format json
```

The image runs as UID/GID `10001:10001`, contains only the application package and runtime dependencies, and excludes local AWS configuration, environment files, tests, Git metadata and generated reports. The example uses Terraform JSON and requires no AWS credentials.

For AWS-source scans, provide credentials through the standard AWS credential chain at runtime (for example, a short-lived environment or web-identity credential flow, or a read-only mounted credentials file). Never pass credentials as Docker build arguments or bake them into the image. If mounting an AWS credentials directory, mount it read-only and set `AWS_PROFILE` / `AWS_REGION` as needed. Do not mount a developer's full home directory into an untrusted container.

The CI job builds the image and performs an offline smoke scan. It does not validate a live AWS account. For release images, publish immutable version tags and record the image digest; periodically rebuild the base image and review dependency updates and vulnerability scan results. The Python base tag and package dependency ranges are intentionally updated through reviewed pull requests rather than silently changing application code.

## Project documentation

The [project documentation](docs/README.md) provides deeper notes on architecture, rule development, testing and validation, including [CI/CD scanning](docs/ci-cd-scanning.md). These pages are maintained alongside the code as the project evolves.

## Design

The current processing path is:

```text
Fixtures / Terraform JSON / AWS APIs
                 |
                 v
         Resource normalisation
                 |
                 v
             Rule engine
                 |
                 v
       Evidence-based findings
                 |
                 v
             Reporting
```

The `Resource` model separates source-specific discovery from security rules. This design is already useful, but large architectural changes are intentionally deferred while functional coverage is expanded.

## Development and tests

Requirements: Python 3.11+, boto3, PyYAML and Rich. Pytest is used for development.

```bash
git clone https://github.com/ledgejigsaw/AWS-Security-Scanner.git
cd AWS-Security-Scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest -q
```

The latest pull-request CI runs passed on Python 3.11 and 3.13 after the registry and Lambda lifecycle changes. Test counts change as tests evolve; use the latest GitHub Actions run as the authoritative result. Test results confirm mocked/fixture behaviour, not live-account correctness.

AWS API calls are mocked in automated tests. These tests establish expected behaviour without AWS costs or credentials; they do not replace validation against a real account.

## Roadmap

Roadmap status is based on the current repository code and tests, not on the previous README's stale checklist.

### Implemented in code

- [x] Python package, CLI, `Resource`, `Finding` and rule models
- [x] Decorator-based rule registration and rule engine
- [x] Fixture provider and Terraform JSON provider
- [x] Terraform relationship resolution and S3 resource aggregation
- [x] S3 checks S3-001 through S3-013
- [x] IAM, EC2 and VPC/network rule modules
- [x] Read-only AWS discovery methods for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS and API Gateway REST API stages
- [x] CloudTrail logging, multi-region and log-file validation checks
- [x] KMS automatic-rotation, pending-deletion and broad wildcard key-policy checks
- [x] YAML policy loading, per-rule enable/disable and severity overrides
- [x] JSON, self-contained HTML and SARIF 2.1.0 reporting
- [x] Mocked provider, rule, CLI and integration tests
- [x] IAM-006 severity corrected to INFO: an active key alone is not proof of a vulnerability
- [x] Register IAM-010, IAM-011 and IAM-012 so the existing privilege-escalation, sensitive-action and broad-trust checks execute
- [x] Wire IAM user and account-level credential-report resources into the AWS CLI scan path
- [x] Add SARIF output for CI/code-scanning ingestion
- [x] Add GitHub Actions test workflow for Python 3.11 and 3.13
- [x] Add minimum-severity filtering after policy overrides
- [x] Add versioned JSON finding baselines with stable fingerprints and suppression

### In progress

- [x] Add continuation-token pagination for S3 bucket listing and EC2 resource discovery
- [x] Fail explicitly when IAM credential-report data is missing, stale, not ready or incomplete
- [x] Add regression tests for pagination and unavailable credential-report data
- [ ] Validate AWS discovery and credential-report edge cases against a non-production account

### Next feature batches

1. **Additional AWS coverage:** WAF/application-edge posture, EC2/EBS/snapshot protection, extended S3 controls and AWS-native security-service integrations.
2. **Lifecycle and data quality:** refresh the reviewed Lambda runtime lifecycle snapshot before release, then broaden CloudTrail/KMS account-wide coverage.
3. **Triage and reporting:** finding deduplication, baseline comparison/diffs and more explicit suppression controls.
4. **Infrastructure-as-code coverage:** additional Terraform resource relationships and direct HCL parsing.
5. **Delivery workflow and engineering:** contributor guide, rule metadata validation, packaging checks and CI/CD scanning examples.

### API Gateway scope and limitations

- The initial implementation covers API Gateway **REST APIs (v1)** only; API Gateway HTTP APIs (v2) are not yet discovered.
- A method configured with `authorizationType=NONE` is flagged only when the API has no resource policy. Public endpoint presence alone is not considered a vulnerability.
- Stage access logging is assessed from the stage's `accessLogSettings` destination and format. Missing stages, methods or incomplete settings are not treated as proof of a separate weakness.
- Discovery uses metadata APIs only and does not invoke API endpoints or change configuration.

### Not yet verified or implemented

- [ ] End-to-end scan against a real AWS account (not yet performed)
- [ ] Direct Terraform HCL parsing
- [x] RDS discovery and four baseline security checks
- [x] Lambda discovery and two baseline security checks
- [x] Secrets Manager metadata discovery and two baseline security checks
- [x] ECR repository discovery and two baseline security checks
- [x] DynamoDB table discovery and three baseline security checks
- [x] SQS queue and SNS topic discovery with access-policy and encryption checks
- [x] API Gateway REST API stage discovery, method-authorization and access-logging checks
- [x] ECS task-definition and service discovery, with baseline container-hardening and public-IP checks
- [ ] Additional CloudTrail/KMS account-wide coverage
- [x] Initial maintained Lambda runtime lifecycle snapshot and deprecated-runtime check (refresh against AWS before release)
- [x] Initial CloudFront distribution checks (review scope and false positives before release)
- [x] Initial regional Security Hub and GuardDuty enablement posture checks (native findings are not imported)
- [x] Extended S3 ACL, Object Ownership and MFA Delete review checks (metadata-only; MFA Delete is informational)
- [ ] Multi-account scanning and compliance reporting (tracked in GitHub issues)
- [ ] Finding deduplication, baseline diffs and suppression reason/expiry metadata
- [ ] Automated code-scanning upload and CI/CD scanning examples
- [ ] Architecture visualisation

## Project goals

This project is intended to demonstrate practical experience in Python, AWS security, IAM, infrastructure-as-code analysis, security automation, testing, API integration and security reporting.

Repository: https://github.com/ledgejigsaw/AWS-Security-Scanner
