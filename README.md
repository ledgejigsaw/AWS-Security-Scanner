# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources, Terraform JSON and Terraform HCL. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture, Terraform JSON and partial Terraform HCL scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS, API Gateway REST API stages, ECS task definitions and ECS services, and CloudFront distributions, regional and CloudFront-scope WAFv2 Web ACLs, and Application Load Balancers with WAF association metadata, plus regional Security Hub, GuardDuty and AWS Config posture discovery, with optional bounded import of native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings. Live-account validation has not yet been completed.

## At a glance

- **111 registered security rules:** 17 S3, 17 IAM, 12 EC2, 4 EBS, 10 VPC/network, 5 CloudTrail, 1 Security Hub, 1 GuardDuty, 3 AWS Config, 1 Macie, 4 KMS, 5 RDS, 4 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 4 API Gateway, 7 ECS, 4 CloudFront, 2 WAF and 1 Application Load Balancer check.
- **Test status:** CI runs the automated suite on Python 3.11 and 3.13; check the latest Actions run for the current branch status.
- **Inputs:** local JSON fixtures, Terraform JSON, Terraform HCL and AWS APIs.
- **Output:** JSON, self-contained HTML and SARIF 2.1.0 reporting, with minimum-severity filtering, versioned baseline comparison and expiry-aware suppression.
- **AWS access:** read-only API calls; tests use mocks and do not require AWS credentials.

Automated tests use mocks and fixtures; they do not replace validation against a real AWS account. Live scans remain unverified.

## Interactive CLI

Run the guided setup when you want to configure a scan through questions rather than remember flags:

```bash
aws-security-scan --interactive
```

The wizard asks for the source (fixture directory, Terraform JSON, Terraform HCL or live AWS), assessment scope, report format and destination, and optional policy, compliance mapping, severity filter, resource graph and baseline operation. For AWS scans, choose a quick core-service scan, all supported discovery domains, a comprehensive scan including bounded native Security Hub and GuardDuty findings, or a custom service list. The wizard displays the selected configuration and asks for confirmation before scanning. Enter `q` at a numbered choice to cancel.

For AWS, supply an AWS shared-config profile name or use the default credential chain. The scanner never asks for access keys or secret keys and does not change AWS configuration. Interactive mode is intended for humans; keep explicit flags for scripts and CI, for example:

```bash
aws-security-scan --source hcl --file main.tf --format sarif --output reports/iac.sarif
```

## Capabilities

### Sources

**Fixtures** provide deterministic, offline test inputs.

**Terraform JSON** can be generated from a plan/state representation with:

```bash
terraform show -json > terraform.json
```

The Terraform JSON provider normalises resource data and resolves/aggregates related S3 resources, including bucket encryption, versioning, public-access-block, logging, lifecycle and bucket-policy configuration. The direct HCL provider uses `python-hcl2` for offline static analysis; it does not evaluate variables/locals, expand modules, or execute Terraform. Unresolved expressions and unexpanded modules produce informational diagnostics. See [rule coverage](docs/rule-coverage.md) for the supported subset.

**AWS APIs** are accessed through boto3 in read-only mode. Use `--profile` to select a profile from the standard AWS shared configuration/credentials files, and repeat `--service` to limit discovery to specific supported service domains. Without `--service`, the scanner runs its full supported discovery scope. For example:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service s3 --service iam --format json --output reports/s3-iam.json
```

Supported service selectors are `s3`, `iam`, `ec2`, `ebs`, `vpc`, `cloudtrail`, `kms`, `rds`, `lambda`, `secretsmanager`, `ecr`, `dynamodb`, `sqs`, `sns`, `apigateway`, `ecs`, `cloudfront`, `waf`, `elb`, `securityhub`, `guardduty`, `config` and `macie`. These filters select discovery domains, not individual rule IDs. The profile name is not a credential and no credentials are accepted as command-line arguments. Profile and service options apply only to `--source aws`; the multi-account role-assumption mode uses the caller's default credential chain in this release.

The provider contains discovery methods for S3 buckets, IAM policies, roles, users and account-level credential-report settings, EC2 instances/security groups, EBS volumes and owned snapshots, VPCs, subnets, route tables, network ACLs, VPC flow logs, CloudTrail trails, KMS keys, RDS DB instances, Lambda functions, Secrets Manager secret metadata, ECR repositories, DynamoDB table metadata, SQS queue attributes, SNS topic attributes and API Gateway REST and HTTP API stages, including method/route authorization metadata and stage access-log settings, plus ECS task-definition container settings and ECS service network configuration, and regional Security Hub hub status, GuardDuty detector status and AWS Config recorder/recording/delivery-channel status, and regional Amazon Macie session status. Native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings can be imported explicitly with `--include-native-findings`; imported findings retain source identifiers and timestamps where available. API discovery and rule coverage are not the same thing: some resource types have more comprehensive checks than others. A live AWS account has not yet been used for end-to-end validation. Secrets Manager discovery reads metadata and resource policies only; it never retrieves secret values.

WAF/application-edge discovery additionally covers regional and CloudFront-scope WAFv2 Web ACL metadata and Application Load Balancer WAF association state. See [WAF and application-edge posture](docs/waf-application-edge.md) for scope and limitations.

### Security checks

| Service | Coverage |
| --- | --- |
| S3 | Public exposure, encryption, versioning, Block Public Access, server-access logging, bucket-policy risks, public ACL grants, ACL-based ownership, MFA Delete, cross-account policy and Object Lock review signals |
| IAM | Unrestricted and broad permissions, high-risk administrative actions, role trust policies, MFA, access-key state/age/inactivity, password/console credential hygiene and unused roles |
| EC2 | SSH/RDP and sensitive-port exposure, broad ingress/egress, public IPv4, IMDSv1 and broad IPv6 rules; detailed monitoring and missing instance-profile checks are informational review signals |
| EBS | Explicitly unencrypted volumes/snapshots and snapshots with an observed public create-volume permission; denied permission discovery remains unknown |
| VPC/network | Public subnet configuration, internet routes, broad IPv4/IPv6 routes, network ACL ingress/egress and default NACL checks |
| CloudTrail | Trail logging status, multi-region coverage, log-file validation, CloudWatch Logs integration review and recent delivery errors |
| Security Hub | Regional hub enablement posture; optional import of up to 100 native findings by default (limit configurable to 1,000), preserving source IDs, product ARNs and observation timestamps |
| GuardDuty | Regional detector enablement posture and optional bounded native-finding import, preserving source IDs and timestamps |
| AWS Config | Regional recorder status, recording state and delivery-channel presence; API permission failures are not treated as disabled state |
| Amazon Macie | Regional session enablement/paused status; does not assess discovery-job coverage or delegated-administrator configuration |
| KMS | Automatic rotation, pending deletion, broad wildcard key-policy access and unconditional cross-account access to sensitive KMS actions as a review signal |
| RDS | Storage encryption, public accessibility, automated-backup retention and deletion protection |
| Lambda | Function URLs configured with unauthenticated access, unconditional wildcard-principal invocation policies and runtimes explicitly listed as deprecated in the reviewed AWS lifecycle snapshot |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |
| API Gateway (REST and HTTP APIs) | REST methods and HTTP API routes configured with no authorization; stage access logging not configured |
| WAFv2 | Managed rule group and rate-based rule coverage review signals; CloudFront-scope ACLs use the global WAF endpoint in us-east-1 |
| Application Load Balancers | Missing WAF association as an informational review signal; network load balancers are not included | 
| ECS / Fargate | Privileged containers, host network mode, explicitly configured root users, writable container root filesystems and services assigning public IP addresses |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains 111 rules (17 S3, 17 IAM, 12 EC2, 4 EBS, 10 VPC/network, 5 CloudTrail, 1 Security Hub, 1 GuardDuty, 3 AWS Config, 1 Macie, 4 KMS, 5 RDS, 4 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway, 7 ECS, 4 CloudFront, 2 WAF and 1 Application Load Balancer). Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

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

### Optional explainable risk scoring

Add per-finding risk scores without replacing severity:

```bash
aws-security-scan --source terraform --file tests/fixtures/terraform/realistic_s3.json --risk-score --format json
```

Use `--risk-config risk.json` with `--risk-score` to configure explicit exposure/confidence overrides by check ID and criticality bonuses by exact resource ID. Scores and factor explanations are omitted by default for backwards-compatible reports. The model is a deterministic triage index, not a breach probability; see [risk scoring](docs/risk-scoring.md) for the versioned formula and limitations.

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

Opt in to import bounded native AWS Security Hub and GuardDuty findings from the selected region:

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

Native finding import is disabled by default. It queries Security Hub and GuardDuty in the selected region and requires `securityhub:GetFindings`, `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings`, `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindingsV2`, `inspector2:ListFindings`, `macie2:ListFindings` and `macie2:GetFindings`. The default cap is 100 findings per source; the supported limit is 1–1,000 per source. The scanner follows pagination up to each cap, deduplicates repeated source IDs, and lets API errors propagate rather than reporting an empty result. GuardDuty-backed Security Hub products are excluded from the Security Hub import when direct GuardDuty ingestion is enabled to avoid importing the same product through both APIs. Imported entries use `AWS-SHUB-NATIVE`, `AWS-GD-NATIVE`, `AWS-AA-NATIVE`, `AWS-INSPECTOR-NATIVE` or `AWS-MACIE-NATIVE` and preserve source type, source finding ID, account ID and observation timestamps where available. JSON, HTML and SARIF distinguish native findings from scanner-generated checks. Native source identity is included in baseline fingerprints so multiple findings on one resource do not collapse together.

Do not commit credentials, account exports containing sensitive data, or generated reports. Use a least-privilege read-only identity and validate required IAM permissions before scanning a production account.

## Resource graph export

Add `--graph-output` to a single-account scan to write a separate machine-readable resource graph:

```bash
aws-security-scan --source terraform --file terraform.json --graph-output reports/resource-graph.json
```

The graph contains safe resource identity metadata, explicit resolved relationships with provenance/confidence, unresolved references marked as unknown, and finding check IDs linked only when the resource match is unambiguous. It deliberately excludes raw resource attributes, policies, secret values and object contents. It does not infer network reachability: an absent edge is not evidence of isolation. Multi-account graph output is not supported in this increment.

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
Fixtures / Terraform JSON / Terraform HCL / AWS APIs
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

Status reflects repository code and automated tests. All provider tests are mocked or fixture-based; **live AWS end-to-end validation has not been performed**.

### Implemented and tested offline

- [x] Fixture, Terraform JSON and partial Terraform HCL sources.
- [x] Read-only AWS discovery across the services listed above, including AWS Config, Security Hub, GuardDuty and Amazon Macie posture.
- [x] Native Security Hub and GuardDuty finding import, with source identity and deduplication.
- [x] Multi-account scans through explicit cross-account audit roles, expected-account validation and partial-failure reporting.
- [x] JSON, self-contained HTML and SARIF reports; optional compliance mapping.
- [x] Severity filtering, YAML policy overrides, baseline creation, suppression, diffs and expiry metadata.
- [x] Deterministic resource graph JSON with conservative relationship provenance.
- [x] CI on Python 3.11 and 3.13 plus container and offline fixture smoke tests.

### Limitations and next work

1. **AWS-native integrations:** extend Issue #32 with IAM Access Analyzer findings; assess Macie and Inspector separately before adding their broader APIs.
2. **S3 access analysis:** continue Issue #36 with condition-aware cross-account bucket-policy analysis and policy-dependent Object Lock signals; do not fetch object contents.
3. **Explainable risk:** Issue #47 proposes optional, versioned risk scores distinct from severity; scores must not be represented as breach probabilities.
4. **Multi-cloud architecture:** Issues #58–#60 cover provider-neutral interfaces and future Azure/GCP providers. Azure and GCP are planned, not supported.
5. **Repository quality:** keep rule inventory, coverage docs, CLI options and examples synchronized with implementation; refresh lifecycle snapshots before releases.
6. **Live validation:** perform a least-privilege test against a non-production AWS account before claiming end-to-end validation.

## Project goals

This project is intended to demonstrate practical experience in Python, AWS security, IAM, infrastructure-as-code analysis, security automation, testing, API integration and security reporting.

Repository: https://github.com/ledgejigsaw/AWS-Security-Scanner
