# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources and Terraform JSON. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture and Terraform JSON scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS and SNS resources. Live-account validation has not yet been completed.

## At a glance

- **70 registered security rules:** 10 S3, 17 IAM, 10 EC2, 10 VPC/network, 3 CloudTrail, 3 KMS, 4 RDS, 2 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS and 2 SNS checks.
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

**AWS APIs** are accessed through boto3 in read-only mode. The provider contains discovery methods for S3 buckets, IAM policies, roles, users and account-level credential-report settings, EC2 instances/security groups, VPCs, subnets, route tables, network ACLs, VPC flow logs, CloudTrail trails, KMS keys, RDS DB instances, Lambda functions, Secrets Manager secret metadata, ECR repositories, DynamoDB table metadata, SQS queue attributes and SNS topic attributes. API discovery and rule coverage are not the same thing: some resource types have more comprehensive checks than others. A live AWS account has not yet been used for end-to-end validation. Secrets Manager discovery reads metadata and resource policies only; it never retrieves secret values.

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
| Lambda | Function URLs configured with unauthenticated access and unconditional wildcard-principal invocation policies |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains 70 rules (10 S3, 17 IAM, 10 EC2, 10 VPC/network, 3 CloudTrail, 3 KMS, 4 RDS, 2 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS and 2 SNS). Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

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

The latest confirmed local baseline on `main` before this SQS/SNS change was 339 passing tests. The current branch's test results are reported by GitHub Actions; do not treat the baseline as validation of unmerged changes.

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
- [x] Read-only AWS discovery methods for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS and SNS resources
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

1. **Additional AWS coverage:** API Gateway and ECS/Fargate checks with mocked discovery and tests.
2. **Lifecycle and data quality:** maintained Lambda runtime lifecycle data, then broaden CloudTrail/KMS account-wide coverage.
3. **Triage and reporting:** finding deduplication, baseline comparison/diffs and more explicit suppression controls.
4. **Infrastructure-as-code coverage:** additional Terraform resource relationships and direct HCL parsing.
5. **Delivery workflow and engineering:** contributor guide, rule metadata validation, packaging checks and CI/CD scanning examples.

### Not yet verified or implemented

- [ ] End-to-end scan against a real AWS account (not yet performed)
- [ ] Direct Terraform HCL parsing
- [x] RDS discovery and four baseline security checks
- [x] Lambda discovery and two baseline security checks
- [x] Secrets Manager metadata discovery and two baseline security checks
- [x] ECR repository discovery and two baseline security checks
- [x] DynamoDB table discovery and three baseline security checks
- [x] SQS queue and SNS topic discovery with access-policy and encryption checks
- [ ] Additional CloudTrail/KMS account-wide coverage and maintained Lambda runtime lifecycle data
- [ ] Finding deduplication, baseline diffs and suppression reason/expiry metadata
- [ ] Automated code-scanning upload and CI/CD scanning examples
- [ ] Architecture visualisation

## Project goals

This project is intended to demonstrate practical experience in Python, AWS security, IAM, infrastructure-as-code analysis, security automation, testing, API integration and security reporting.

Repository: https://github.com/ledgejigsaw/AWS-Security-Scanner
