# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources and Terraform JSON. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture and Terraform JSON scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS, API Gateway REST API stages, ECS task definitions and ECS services, and CloudFront distributions. Live-account validation has not yet been completed.

## At a glance

- **79 registered security rules after the planned ECS-006 and LAMBDA-003 additions are merged:** 10 S3, 17 IAM, 10 EC2, 10 VPC/network, 3 CloudTrail, 3 KMS, 4 RDS, 3 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway and 6 ECS checks.
- **Test status:** CI runs the automated suite on Python 3.11 and 3.13; check the latest Actions run for the current branch status.
- **Inputs:** local JSON fixtures, Terraform JSON and AWS APIs.
- **Output:** JSON, self-contained HTML and SARIF 2.1.0 reporting, with minimum-severity filtering and baseline suppression.
- **AWS access:** read-only API calls; tests use mocks and do not require AWS credentials.

Automated tests use mocks and fixtures; they do not replace validation against a real AWS account. Live scans remain unverified.

## Capabilities

### Sources

**Fixtures** provide deterministic, offline test inputs.

**Terraform JSON** can be generated from a plan/state representation with:

```bash
terraform show -json > terraform.json
```

The Terraform provider normalises resource data and resolves/aggregates related S3 resources, including bucket encryption, versioning, public-access-block, logging and bucket-policy configuration. Direct HCL parsing is not currently implemented.

**AWS APIs** are accessed through boto3 in read-only mode. The provider contains discovery methods for S3 buckets, IAM policies, roles, users and account-level credential-report settings, EC2 instances/security groups, VPCs, subnets, route tables, network ACLs, VPC flow logs, CloudTrail trails, KMS keys, RDS DB instances, Lambda functions, Secrets Manager secret metadata, ECR repositories, DynamoDB table metadata, SQS queue attributes, SNS topic attributes and API Gateway REST API stages, including method authorization metadata and stage access-log settings, plus ECS task-definition container settings and ECS service network configuration. API discovery and rule coverage are not the same thing: some resource types have more comprehensive checks than others. A live AWS account has not yet been used for end-to-end validation. Secrets Manager discovery reads metadata and resource policies only; it never retrieves secret values.

### Security checks

| Service | Coverage |
| --- | --- |
| S3 | Public exposure, encryption, versioning, Block Public Access, server-access logging, risky bucket-policy principals/actions/resources, TLS enforcement and public write access |
| IAM | Unrestricted and broad permissions, high-risk administrative actions, role trust policies, MFA, access-key state/age/inactivity, password/console credential hygiene and unused roles |
| EC2 | SSH/RDP and sensitive-port exposure, broad ingress/egress, public IPv4, IMDSv1 and broad IPv6 rules |
| VPC/network | Public subnet configuration, internet routes, broad IPv4/IPv6 routes, network ACL ingress/egress and default NACL checks |
| CloudTrail | Trail logging status, multi-region coverage and log-file validation |
| KMS | Automatic rotation, pending deletion and broad wildcard key-policy access |
| RDS | Storage encryption, public accessibility, automated-backup retention and deletion protection |
| Lambda | Function URLs configured with unauthenticated access, unconditional wildcard-principal invocation policies and runtimes explicitly listed as deprecated in the reviewed AWS lifecycle snapshot |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |
| API Gateway (REST APIs) | Methods configured with no authorization when no API resource policy is present; stage access logging not configured |
| ECS / Fargate | Privileged containers, host network mode, explicitly configured root users, writable container root filesystems and services assigning public IP addresses |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains 78 rules (10 S3, 17 IAM, 10 EC2, 10 VPC/network, 3 CloudTrail, 3 KMS, 4 RDS, 2 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway and 5 ECS). Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

### Policy and reporting

YAML policy files can enable/disable individual checks and override their severity. JSON reports include a summary and structured findings with check ID, severity, resource, description, remediation, region and evidence where available. HTML reports provide a self-contained table for human review. SARIF 2.1.0 output maps scanner severities to SARIF levels and includes resource/evidence metadata for code-scanning ingestion.

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

The baseline uses a stable fingerprint derived from check ID, service, resource and region; changing evidence text does not create a new finding identity. A baseline suppresses matching findings from the report—it does not disable checks or alter the underlying rules. Use `--write-baseline` to explicitly replace/update the known-findings baseline after reviewing the current findings. The two baseline options are mutually exclusive.

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

Do not commit credentials, account exports containing sensitive data, or generated reports. Use a least-privilege read-only identity and validate required IAM permissions before scanning a production account.

## Project documentation

The [project documentation](docs/README.md) provides deeper notes on architecture, rule development, testing and validation. These pages are maintained alongside the code as the project evolves.

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
- [x] S3 checks S3-001 through S3-010
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
- [x] Initial CloudFront distribution checks (review scope and false positives before release)\n- [ ] WAF, AWS security-service posture, multi-account scanning and compliance mapping (tracked in GitHub issues)
- [ ] Finding deduplication, baseline diffs and suppression reason/expiry metadata
- [ ] Automated code-scanning upload and CI/CD scanning examples
- [ ] Architecture visualisation

## Project goals

This project is intended to demonstrate practical experience in Python, AWS security, IAM, infrastructure-as-code analysis, security automation, testing, API integration and security reporting.

Repository: https://github.com/ledgejigsaw/AWS-Security-Scanner
