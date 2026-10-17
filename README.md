# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources, Terraform JSON and Terraform HCL. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture, Terraform JSON and partial Terraform HCL scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS, API Gateway REST API stages, ECS task definitions and ECS services, and CloudFront distributions, regional and CloudFront-scope WAFv2 Web ACLs, and Application Load Balancers with WAF association metadata, plus regional Security Hub, GuardDuty and AWS Config posture discovery, with optional bounded import of native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings. Live-account validation has not yet been completed.

## At a glance

- **123 registered security rules:** 17 S3, 17 IAM, 12 EC2, 4 EBS, 10 VPC/network, 6 CloudTrail, 1 Security Hub, 1 GuardDuty, 3 AWS Config, 1 Macie, 5 KMS, 5 RDS, 4 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway, 7 ECS, 4 CloudFront, 2 WAF, 4 Application Load Balancer, 3 EKS, 2 CloudWatch and 2 EFS checks.
- **Test status:** CI runs the automated suite on Python 3.11 and 3.13; check the latest Actions run for the current branch status.
- **Inputs:** local JSON fixtures, Terraform JSON, Terraform HCL and AWS APIs.
- **Output:** JSON, self-contained HTML, SARIF 2.1.0 and OCSF 1.7.0 reporting, with minimum-severity filtering, versioned baseline comparison and expiry-aware suppression.
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

**Terraform JSON** can be generated from a reviewed plan with `terraform show -json`. The scanner accepts the plan structure, records unknown planned attributes and create/update/delete actions, and emits informational diagnostics when a final value is not yet known. It does not execute Terraform or download providers/modules. The legacy normalised JSON input remains supported.

Generate a plan JSON file with:

```bash
terraform show -json > terraform.json
```

The Terraform JSON provider normalises resource data and resolves/aggregates related S3 resources, including bucket encryption, versioning, public-access-block, logging, lifecycle and bucket-policy configuration. The direct HCL provider uses `python-hcl2` for offline static analysis; it does not evaluate variables/locals, expand modules, or execute Terraform. Unresolved expressions and unexpanded modules produce informational diagnostics. See [rule coverage](docs/rule-coverage.md) for the supported subset.

**AWS APIs** are accessed through boto3 in read-only mode. Use `--profile` to select a profile from the standard AWS shared configuration/credentials files, and repeat `--service` to limit discovery to specific supported service domains. Without `--service`, the scanner runs its full supported discovery scope. For example:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service s3 --service iam --format json --output reports/s3-iam.json
```

Supported service selectors are `s3`, `iam`, `ec2`, `ebs`, `vpc`, `cloudtrail`, `kms`, `rds`, `lambda`, `secretsmanager`, `ecr`, `dynamodb`, `sqs`, `sns`, `apigateway`, `ecs`, `cloudfront`, `waf`, `elb`, `securityhub`, `guardduty`, `config`, `macie`, `eks`, `cloudwatch` and `efs`. These filters select discovery domains, not individual rule IDs. The profile name is not a credential and no credentials are accepted as command-line arguments. Profile and service options apply only to `--source aws`; the multi-account role-assumption mode uses the caller's default credential chain in this release.

The provider contains discovery methods for S3 buckets, IAM policies, roles, users and account-level credential-report settings, EC2 instances/security groups, EBS volumes and owned snapshots, VPCs, subnets, route tables, network ACLs, VPC flow logs, CloudTrail trails, KMS keys, RDS DB instances, Lambda functions, Secrets Manager secret metadata, ECR repositories, DynamoDB table metadata, SQS queue attributes, SNS topic attributes and API Gateway REST and HTTP API stages, including method/route authorization metadata and stage access-log settings, plus ECS task-definition container settings and ECS service network configuration, and regional Security Hub hub status, GuardDuty detector status and AWS Config recorder/recording/delivery-channel status, and regional Amazon Macie session status. Native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings can be imported explicitly with `--include-native-findings`; imported findings retain source identifiers and timestamps where available. API discovery and rule coverage are not the same thing: some resource types have more comprehensive checks than others. A live AWS account has not yet been used for end-to-end validation. Secrets Manager discovery reads metadata and resource policies only; it never retrieves secret values.

WAF/application-edge discovery additionally covers regional and CloudFront-scope WAFv2 Web ACL metadata and Application Load Balancer WAF association state. See [WAF and application-edge posture](docs/waf-application-edge.md) for scope and limitations.

### Security Hub native control findings

Native finding ingestion is opt-in and bounded. By default, the Security Hub import requests only `ACTIVE` records, and it can be filtered by workflow status or control compliance status. The imported finding preserves the Security Hub finding ID, product ARN, timestamps, control/generator identifier, compliance state, workflow status and record state where supplied. These are imported source findings, not scanner-authored rule results, and the returned sample is not proof that every standard or control was evaluated.

Examples:

```bash
# Import active findings (bounded to 100 per source by default)
aws-security-scan --source aws --profile security-audit --region eu-west-2 --include-native-findings

# Only failed controls that are new or notified
aws-security-scan --source aws --profile security-audit --region eu-west-2 \
  --include-native-findings \
  --securityhub-compliance-status FAILED \
  --securityhub-workflow-status NEW \
  --securityhub-workflow-status NOTIFIED

# Include archived records as well
aws-security-scan --source aws --profile security-audit --region eu-west-2 \
  --include-native-findings --securityhub-record-state ALL
```

Required permissions include `securityhub:GetFindings` and permission to call `securityhub:DescribeHub` where hub status is checked. The integration is regional; use a region where Security Hub is enabled. Disabled-hub, access-denied and pagination errors are reported as discovery coverage failures rather than silently converted to zero findings. The default per-source limit is 100 (maximum 1,000); reaching the limit may mean the returned sample is incomplete.

### GuardDuty native findings across regions

Native GuardDuty finding import can query more than one region. If no `--guardduty-region` is supplied, the scanner uses `--region`, then the configured AWS region, and finally `us-east-1` if no region is configured. Repeat the option to select an explicit region list. The normal resource-posture discovery region is unchanged; this option expands only native GuardDuty finding ingestion.

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 \
  --include-native-findings \
  --guardduty-region eu-west-2 \
  --guardduty-region us-east-1 \
  --guardduty-record-state ACTIVE \
  --guardduty-updated-after 2026-10-01T00:00:00Z
```

`--guardduty-record-state` accepts `ACTIVE`, `ARCHIVED` or `ALL`; the default `ALL` preserves the previous import behaviour. `--guardduty-updated-after` accepts a timezone-aware ISO-8601 date-time and filters on the finding's update time. Findings are deduplicated by region, account and native finding ID, so matching IDs in different regions are not incorrectly collapsed.

The scanner checks that each selected region has an enabled GuardDuty detector. Missing/disabled detectors, denied permissions, throttling exhaustion or pagination failures are reported as regional coverage gaps; they are not represented as zero findings. Use a read-only identity with the relevant GuardDuty permissions, including `guardduty:ListDetectors`, `guardduty:GetDetector`, `guardduty:ListFindings` and `guardduty:GetFindings`. The limit applies per selected region; results remain bounded and do not establish complete threat-history coverage.

### Security checks

| Service | Coverage |
| --- | --- |
| S3 | Public exposure, encryption, versioning, Block Public Access, server-access logging, bucket-policy risks, public ACL grants, ACL-based ownership, MFA Delete, cross-account policy and Object Lock review signals |
| IAM | Unrestricted and broad permissions, high-risk administrative actions, role trust policies, MFA, access-key state/age/inactivity, password/console credential hygiene and unused roles |
| EC2 | SSH/RDP and sensitive-port exposure, broad ingress/egress, public IPv4, IMDSv1 and broad IPv6 rules; detailed monitoring and missing instance-profile checks are informational review signals |
| EBS | Explicitly unencrypted volumes/snapshots and snapshots with an observed public create-volume permission; denied permission discovery remains unknown |
| VPC/network | Public subnet configuration, internet routes, broad IPv4/IPv6 routes, network ACL ingress/egress and default NACL checks |
| CloudTrail | Trail logging status, organisation-trail metadata, multi-region coverage, basic/advanced event-selector metadata, log-file validation, CloudWatch Logs integration review and recent delivery errors |
| Security Hub | Regional hub enablement posture; optional import of up to 100 native findings by default (limit configurable to 1,000), preserving source IDs, product ARNs and observation timestamps |
| GuardDuty | Regional detector enablement posture and optional bounded native-finding import, preserving source IDs and timestamps |
| AWS Config | Regional recorder status, recording state and delivery-channel presence; API permission failures are not treated as disabled state |
| Amazon Macie | Regional session enablement/paused status; does not assess discovery-job coverage or delegated-administrator configuration |
| KMS | Automatic rotation, pending deletion, broad wildcard key-policy access, unconditional cross-account access and high-impact grant operations as review signals |
| RDS | Storage encryption, public accessibility, automated-backup retention and deletion protection |
| Lambda | Function URLs configured with unauthenticated access, unconditional wildcard-principal invocation policies and runtimes explicitly listed as deprecated in the reviewed AWS lifecycle snapshot |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |
| API Gateway (REST and HTTP APIs) | REST methods and HTTP API routes configured with no authorization; stage access logging not configured |
| WAFv2 | Managed rule group and rate-based rule coverage review signals; CloudFront-scope ACLs use the global WAF endpoint in us-east-1 |
| Application Load Balancers | WAF association, internet-facing HTTP listeners, explicitly known legacy TLS policies and access logging; unknown discovery state is not treated as absence | 
| ECS / Fargate | Privileged containers, host network mode, explicitly configured root users, writable container root filesystems and services assigning public IP addresses |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains 116 rules (17 S3, 17 IAM, 12 EC2, 4 EBS, 10 VPC/network, 6 CloudTrail, 1 Security Hub, 1 GuardDuty, 3 AWS Config, 1 Macie, 5 KMS, 5 RDS, 4 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 2 API Gateway, 7 ECS, 4 CloudFront, 2 WAF and 4 Application Load Balancer). Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

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

For CI automation, add `--summary-output reports/scan-summary.json` to write a versioned summary separately from the detailed report. Use `--fail-on HIGH` to return exit code `3` when any reported finding is HIGH or CRITICAL; incomplete assessments return `1`, invalid CLI/configuration returns `2`, and a completed scan without a threshold breach returns `0`. See [the exit-code contract](docs/scan-summary-and-exit-codes.md).

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

## AWS discovery coverage and partial assessments

For live AWS scans, the CLI reports a status for each selected service domain: `success` (resources discovered), `empty` (discovery completed with no resources), `partial` (some discovery operations succeeded and others failed), or `failed` (all operations for that domain failed). The JSON report includes per-domain counts and bounded diagnostic codes; raw AWS error messages and request payloads are not copied into coverage diagnostics.

A scan with any `partial` or `failed` service domain emits a warning and exits with status 1 after writing the report. This prevents incomplete visibility from being presented as a clean assessment. An `empty` status means discovery succeeded but returned no resources; it does not prove that an unsupported service or unobservable resource is secure. Service selection with `--service` limits the intended scope and is reflected in the coverage entries.

## Resource graph export

Add `--graph-output` to a single-account scan to write a separate machine-readable resource graph:

```bash
aws-security-scan --source terraform --file terraform.json --graph-output reports/resource-graph.json
```

The graph contains safe resource identity metadata, explicit resolved relationships with provenance/confidence, unresolved references marked as unknown, and finding check IDs linked only when the resource match is unambiguous. It deliberately excludes raw resource attributes, policies, secret values and object contents. It does not infer network reachability: an absent edge is not evidence of isolation. Multi-account graph output is not supported in this increment.

## Live AWS authentication and identity check

For `--source aws`, the CLI resolves credentials through boto3's standard AWS credential chain and verifies the active identity with STS before starting discovery. The account ID and principal ARN are printed so the operator can confirm the target. If credentials are missing, the scan stops with setup guidance; the scanner never prompts for, accepts, or stores access keys or secret keys.

Configure a named profile with the AWS CLI, or use IAM Identity Center:

```bash
aws configure --profile audit
# Or, for IAM Identity Center:
aws configure sso --profile audit
aws sso login --profile audit

aws-security-scan --source aws --profile audit --region eu-west-2
```

The profile or default credential chain may also use environment, web-identity, container, or instance-role credentials. Use a dedicated least-privilege read-only identity. STS identity verification is not proof that every service permission is available; service-level access-denied and incomplete-discovery handling remains important. The identity preflight applies to single-account AWS scans; the explicit multi-account workflow validates each assumed-role identity separately. Fixture and IaC scans do not require AWS credentials.


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

## AWS discovery pagination limits

AWS API discovery follows continuation tokens and rejects repeated tokens or truncated responses without a continuation token. Pagination now has a hard safety bound of 1,000 pages per collection by default. If the bound is reached while more results remain, discovery raises an explicit incomplete-discovery error instead of returning a partial resource list as though it were complete. This is a safety bound, not a claim that every service has returned all resources; service APIs and permissions still determine actual coverage.


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

Run the optional offline performance probes (rule evaluation, resource graph, JSON and SARIF report generation) with `python scripts/benchmark_scan.py --sizes 100 500 1000`. See [performance benchmark guidance](docs/performance-benchmarks.md); the timings are environment-specific observations, not CI thresholds.

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


## Compliance mapping example

The scanner supports versioned compliance mappings with `--compliance-mapping`. A partial CIS AWS Foundations Benchmark v1.4.0 example is available at `examples/compliance/cis-aws-foundations-benchmark-1.4.0.json`. It is explicitly illustrative and does not establish certification or complete control coverage; see [compliance mapping examples](docs/compliance-mapping-examples.md).


## OCSF output

Use `--format ocsf` to write an OCSF 1.7.0 Detection Finding JSON array to `reports/scan.ocsf.json`. See [OCSF export](docs/ocsf-export.md).
