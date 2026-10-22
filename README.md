# AWS Security Scanner

A Python-based, read-only cloud security posture assessment tool for AWS resources, Terraform JSON and Terraform HCL. The project is being built as a practical cloud-security engineering portfolio, with reusable rules, evidence-based findings, deterministic tests and CI-friendly output.

> **Current status:** Active development. Fixture, Terraform JSON and partial Terraform HCL scans are available. The AWS provider supports read-only discovery for S3, IAM, EC2, VPC/network, CloudTrail, KMS, RDS, Lambda, Secrets Manager, ECR, DynamoDB, SQS, SNS, API Gateway REST API stages, ECS task definitions and ECS services, and CloudFront distributions, regional and CloudFront-scope WAFv2 Web ACLs, and Application Load Balancers with WAF association metadata, plus regional Security Hub, GuardDuty and AWS Config posture discovery, with optional bounded import of native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings. Live-account validation has not yet been completed.

## Recent implementation batch — 22 October 2026

The following implementation PRs are open for review and have not been merged or locally test-verified:

- [#248 — AWS Backup discovery and recovery checks](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/248) — issue [#231](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/231). Adds read-only Backup vault/plan/protected-resource discovery and a conservative missing-backup-evidence review signal.
- [#249 — Terraform plan source attribution](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/249) — issue [#232](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/232). Optionally links plan resources to HCL files using exact canonical addresses; it does not fabricate source line numbers.
- [#250 — Offline differential benchmark](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/250) — issue [#233](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/233). Adds a versioned expected-outcome runner and manifest; the initial upstream mappings remain not reviewed and make no parity claim.
- [#251 — Rule inventory and upstream mapping ledger](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/251) — issue [#176](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/176). Adds rule source/attribute/test-reference inventory metadata and validation of a versioned mapping ledger.
- [#252 — Terraform static reference resolution and graph export](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/252) — issue [#172](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/172). Adds conservative exact-reference resolution and optional HCL dependency graph JSON output.

These are integrated into the existing CLI and registry where applicable. Unknown, unobserved, and unsupported states remain explicit. No AWS credentials or live-account validation are required for the offline workflows. Run the local pytest suite and the new scripts before merging; no tests were run as part of this batch.

## At a glance

- **129 registered security rules:** 18 S3, 17 IAM, 12 EC2, 4 EBS, 10 VPC/network, 7 CloudTrail, 1 Security Hub, 1 GuardDuty, 3 AWS Config, 1 Macie, 5 KMS, 5 RDS, 4 Lambda, 2 Secrets Manager, 2 ECR, 3 DynamoDB, 2 SQS, 2 SNS, 4 API Gateway (REST and HTTP APIs), 7 ECS, 4 CloudFront, 2 WAF, 4 Application Load Balancer, 3 EKS, 2 CloudWatch, 2 EFS and 2 CodeBuild checks.
- **Test status:** CI runs the automated suite on Python 3.11 and 3.13; check the latest Actions run for the current branch status.
- **Inputs:** local JSON fixtures, Terraform JSON, Terraform HCL, versioned resource snapshots and AWS APIs.
- **Output:** JSON, self-contained HTML, SARIF 2.1.0 and OCSF 1.7.0 reporting, opt-in versioned resource snapshots, minimum-severity filtering, versioned baseline comparison and expiry-aware suppression.
- **AWS access:** read-only API calls; tests use mocks and do not require AWS credentials.

Automated tests use mocks and fixtures; they do not replace validation against a real AWS account. Live scans remain unverified.

## Interactive CLI

Run the guided setup when you want to configure a scan through questions rather than remember flags:

```bash
aws-security-scan --interactive
```

The wizard asks for the source (fixture directory, Terraform JSON, Terraform HCL, a saved resource snapshot or live AWS), assessment scope, report format and destination, and optional policy, compliance mapping, severity filter, resource graph and baseline operation. For AWS scans, choose a quick core-service scan, all supported discovery domains, a comprehensive scan including bounded native Security Hub and GuardDuty findings, or a custom service list. The wizard displays the selected configuration and asks for confirmation before scanning. Enter `q` at a numbered choice to cancel.

For AWS, supply an AWS shared-config profile name or use the default credential chain. The scanner never asks for access keys or secret keys and does not change AWS configuration. Interactive mode is intended for humans; keep explicit flags for scripts and CI, for example:

```bash
aws-security-scan --source hcl --file ./terraform --var-file ./environments/production.tfvars --format sarif --output reports/iac.sarif
```

## Capabilities

### Sources

**Fixtures** provide deterministic, offline test inputs.

**Terraform JSON** can be generated from a reviewed plan with `terraform show -json`. The scanner accepts the plan structure, records unknown planned attributes and create/update/delete actions, and emits informational diagnostics when a final value is not yet known. It does not execute Terraform or download providers/modules. The legacy normalised JSON input remains supported.

Generate a plan JSON file with:

```bash
terraform show -json > terraform.json
```

The Terraform JSON provider normalises resource data and resolves/aggregates related S3 resources, including bucket encryption, versioning, public-access-block, logging, lifecycle and bucket-policy configuration. The direct HCL provider uses `python-hcl2` for offline static analysis and accepts either a single `.tf` file or a module-root directory (all direct-child `.tf` files are parsed together). It loads `terraform.tfvars`, sorted `*.auto.tfvars` files and repeatable explicit `--var-file` inputs in that precedence order; later explicit files override earlier files. It resolves literal variable defaults/overrides, a bounded subset of local references, and supported literal module arguments. It does not execute Terraform, evaluate arbitrary functions, read Terraform environment/CLI variables, or query providers. Relative local modules inside the selected scan root are expanded with bounded recursion; Registry/Git modules are not downloaded. Unresolved expressions, count/for_each and dynamic blocks, unexpanded modules, and unevaluated data sources produce informational diagnostics. Nested directories remain separate module/example boundaries. See [Terraform static-analysis design](docs/terraform-static-analysis.md) and [rule coverage](docs/rule-coverage.md) for the supported subset.

**AWS APIs** are accessed through boto3 in read-only mode. Use `--profile` to select a profile from the standard AWS shared configuration/credentials files, and repeat `--service` to limit discovery to specific supported service domains. Without `--service`, the scanner runs its full supported discovery scope. For example:

```bash
aws-security-scan --source aws --profile security-audit --region eu-west-2 --service s3 --service iam --format json --output reports/s3-iam.json
```

Supported service selectors are `s3`, `iam`, `ec2`, `ebs`, `vpc`, `cloudtrail`, `kms`, `rds`, `lambda`, `secretsmanager`, `ecr`, `dynamodb`, `sqs`, `sns`, `apigateway`, `ecs`, `cloudfront`, `waf`, `elb`, `securityhub`, `guardduty`, `config`, `macie`, `eks`, `cloudwatch`, `efs` and `codebuild`. These filters select discovery domains, not individual rule IDs. The profile name is not a credential and no credentials are accepted as command-line arguments. Profile and service options apply only to `--source aws`; the multi-account role-assumption mode uses the caller's default credential chain in this release.

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
| CloudTrail | Trail logging status, account-versus-organisation scope review, multi-region coverage, basic/advanced event-selector metadata and data-event configuration signals, log-file validation, CloudWatch Logs integration review and recent delivery errors |
| Security Hub | Regional hub enablement posture; optional import of up to 100 native findings by default (limit configurable to 1,000), preserving source IDs, product ARNs and observation timestamps |
| GuardDuty | Regional detector enablement posture and optional bounded native-finding import, preserving source IDs and timestamps |
| AWS Config | Regional recorder status, recording state and delivery-channel presence; API permission failures are not treated as disabled state |
| Amazon Macie | Regional session enablement/paused status; does not assess discovery-job coverage or delegated-administrator configuration |
| KMS | Automatic rotation, disabled/pending-deletion lifecycle, broad wildcard key-policy access, unconditional cross-account access and high-impact grant operations as review signals; grant pagination completeness is tracked |
| RDS | Storage encryption, public accessibility, automated-backup retention and deletion protection |
| Lambda | Function URLs configured with unauthenticated access, unconditional wildcard-principal invocation policies, runtimes explicitly listed as deprecated in the reviewed AWS lifecycle snapshot and code-signing enforcement review |
| Secrets Manager | Explicitly disabled automatic rotation and unconditional wildcard-principal access in resource policies |
| ECR | Mutable image tags and disabled image scanning on push (where the API explicitly reports the setting) |
| DynamoDB | Point-in-time recovery, explicit server-side encryption status and deletion protection |
| SQS | Unconditional wildcard-principal access to sensitive queue actions and explicit encryption status |
| SNS | Unconditional wildcard-principal access to publish/subscribe actions and explicit encryption status |
| API Gateway (REST and HTTP APIs) | REST methods and HTTP API routes configured with no authorization; stage access logging not configured |
| WAFv2 | Managed rule group and rate-based rule coverage review signals; CloudFront-scope ACLs use the global WAF endpoint in us-east-1 |
| Application Load Balancers | WAF association, internet-facing HTTP listeners, explicitly known legacy TLS policies and access logging; unknown discovery state is not treated as absence | 
| ECS / Fargate | Privileged containers, host network mode, explicitly configured root users, writable container root filesystems and services assigning public IP addresses |

Rules are registered centrally and receive the normalised `Resource` model. The current registry contains **129 rules** across the service domains listed above. The registry and [rule-coverage matrix](docs/rule-coverage.md) are the authoritative service-by-service inventory; registered rule counts do not establish semantic completeness or parity with another scanner. Check IDs and severities are defined in the rule implementation; informational observations, such as an active IAM access key by itself, are not automatically treated as vulnerabilities.

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

For live AWS scans, the CLI reports a status for each selected service domain: `success` (resources discovered), `empty` (discovery completed with no resources), `partial` (some discovery operations succeeded and others failed), or `failed` (all operations for that domain failed). Version 1.0.0 coverage entries include scope, per-discovery-function outcomes, operation counts, safe error categories and an operation summary in the JSON assessment. These operation records identify scanner discovery functions, not every nested AWS API call. Raw AWS error messages and request payloads are not copied into coverage diagnostics.

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

This roadmap is ordered by **assessment trustworthiness first, then analysis depth, then breadth**. A large rule count is not a quality metric by itself. The goal is to produce accurate, explainable findings with explicit evidence and honest coverage status.

**Current validation status:** the latest local test run reported by the maintainer is **864 passed, 2 skipped**. Automated tests use fixtures and mocked AWS APIs; **live AWS end-to-end validation has not yet been completed**. Do not interpret passing tests as proof of production-account correctness or full upstream-tool parity.

### Current foundation

- [x] Fixture, Terraform JSON and partial Terraform HCL sources.
- [x] Read-only discovery across the AWS service domains listed in the capability and coverage sections.
- [x] Explicit discovery coverage states, bounded pagination/retries and incomplete-assessment reporting.
- [x] Native Security Hub, GuardDuty, IAM Access Analyzer, Inspector and Macie finding ingestion with bounded results and source identity.
- [x] Explicit cross-account role scans with account identity validation and partial-failure reporting.
- [x] JSON, self-contained HTML, SARIF and OCSF output; policy overrides, compliance annotations, baselines, diffs and expiry-aware suppressions.
- [x] Deterministic resource graph output with conservative relationship provenance.
- [x] Offline HCL benchmark corpus, rule inventory export, container smoke tests and CI on Python 3.11/3.13.

### Phase 0 — keep evidence and documentation trustworthy

1. **Prevent inventory drift:** [#234 — generate rule inventory and coverage artefacts in CI](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/234). Ensure README counts, per-service totals, selector documentation and rule-coverage tables cannot silently diverge from the registry.
2. **Maintain a semantic upstream gap ledger:** [#176 — versioned Prowler/ScoutSuite/Checkov gap analysis](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/176). Compare exact scope, conditions, permissions, severity, unknown-state behaviour and tests; do not claim parity based on similar names.
3. **Validate against a controlled AWS account:** [#121 — live-AWS verification plan](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/121). Use a dedicated non-production account and least-privilege read-only identity; test identity, discovery, denied permissions, pagination and regional behaviour without changing resources.

### Phase 1 — improve accuracy and completeness

4. **IAM policy semantics:** [#227 — conditions, policy constructs and effective-access boundaries](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/227). Model supported IAM policy constructs explicitly and distinguish observed risks from missing evaluation context.
5. **Network reachability:** [#228 — resolve routes, security groups, ACLs and endpoint relationships](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/228). Report a reachable path only when evidence supports the complete path; unknown edges must not be treated as isolation.
6. **Regional coverage:** [#229 — opt-in all-enabled-region discovery](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/229). Preserve explicit scope and report each region's outcome; global services require separate handling.

### Phase 2 — deepen Infrastructure-as-Code analysis

7. **Project-wide dependency resolution:** [#172 — Terraform HCL dependency graph](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/172). Resolve supported cross-file and local-module relationships before rule evaluation.
8. **Safe external module support:** [#174 — opt-in external module resolution](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/174). Keep remote fetching disabled by default; require pinned sources, explicit trust and bounded cache behaviour.
9. **Plan-to-source enrichment:** [#232 — link plan findings to HCL source and reliable locations](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/232). Preserve planned unknowns and actions; never invent source line numbers or evaluate unsupported expressions.

### Phase 3 — expand high-value AWS security coverage

10. **Analytics, database and search services:** [#230 — prioritise OpenSearch, Redshift, ElastiCache, MSK and AWS Backup](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/230). Add service discovery and a small, tested set of high-confidence controls in separate increments.
11. **Backup and recovery posture:** [#231 — AWS Backup, retention, replication and recovery signals](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/231). Distinguish backup configuration from freshness and tested restoreability.
12. **Native finding enrichment:** [#113 — Security Hub standards/control findings](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/113) and [#114 — GuardDuty filters and multi-region coverage](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/114). Keep imports bounded and clearly distinguish imported findings from scanner-authored checks.
13. **Broader provider direction:** [#58 — provider-neutral architecture](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/58), [#59 — Azure provider](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/59) and [#60 — GCP provider](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/60). Treat these as later-stage work after AWS evidence quality and shared interfaces are stable.

### Phase 4 — prove quality rather than assume parity

14. **Differential benchmark:** [#233 — versioned comparison against Prowler and Checkov](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/233). Track reviewed mappings, false positives/negatives, unknown outcomes and upstream versions using reproducible offline fixtures, with live comparisons opt-in.
15. **Attack-path analysis:** only after IAM semantics and network relationships are trustworthy. Paths must contain explicit edges, provenance, assumptions and unresolved relationships; resource proximity alone is not evidence of exploitability.

### Competitor positioning and boundaries

- **Prowler** is the primary reference for live cloud posture checks, AWS service breadth, compliance-oriented controls and native integrations: [repository](https://github.com/prowler-cloud/prowler).
- **Checkov** is the primary reference for IaC policy breadth, Terraform plan enrichment, graph context and CI output: [repository](https://github.com/bridgecrewio/checkov).
- **Trivy** is a reference for developer-focused IaC scanning and CI workflows: [repository](https://github.com/aquasecurity/trivy).
- **ScoutSuite** is a reference for multi-service inventory, offline review and honest visibility boundaries: [repository](https://github.com/nccgroup/ScoutSuite).
- **Cloudsplaining and Parliament** are references for IAM policy risk analysis and policy linting: [Cloudsplaining](https://github.com/salesforce/cloudsplaining), [Parliament](https://github.com/duo-labs/parliament).

These projects have different purposes, maturity, licensing and coverage. The aim is to learn from documented controls and benchmark behaviour—not to copy code blindly or claim equivalence without per-check evidence.

### Roadmap rules

- Every new rule needs positive, negative and unknown/incomplete tests, stable metadata, evidence, remediation and a documented permission requirement.
- Provider discovery must distinguish success, empty, partial and failed states; access denied is not equivalent to “no findings.”
- Do not retrieve secret values, database rows, object contents, queue messages or other customer payloads for posture checks.
- Update registry inventory, rule coverage, README and relevant examples in the same change.
- Keep Azure/GCP, account-wide organisation discovery and full effective-permission simulation as explicit future scope until their prerequisites are implemented and tested.
- Reassess priorities after each phase using the benchmark ledger and live-validation evidence, not rule count alone.

## Project goals

This project is intended to demonstrate practical experience in Python, AWS security, IAM, infrastructure-as-code analysis, security automation, testing, API integration and security reporting.

Repository: https://github.com/ledgejigsaw/AWS-Security-Scanner


## Compliance mapping example

The scanner supports versioned compliance mappings with `--compliance-mapping`. A partial CIS AWS Foundations Benchmark v1.4.0 example is available at `examples/compliance/cis-aws-foundations-benchmark-1.4.0.json`. It is explicitly illustrative and does not establish certification or complete control coverage; see [compliance mapping examples](docs/compliance-mapping-examples.md).


## OCSF output

Use `--format ocsf` to write an OCSF 1.7.0 Detection Finding JSON array to `reports/scan.ocsf.json`. See [OCSF export](docs/ocsf-export.md).


## Resource snapshots

Use `--snapshot-output reports/inventory.json` to save a versioned, redacted inventory for offline rule re-analysis. Replay it with `--source snapshot --file reports/inventory.json`. Snapshots are opt-in and may contain sensitive infrastructure metadata; see [resource snapshots](docs/resource-snapshots.md).


## Offline Terraform benchmark and rule inventory

Run the checked-in Terraform HCL regression corpus (secure, insecure and unresolved cases) without AWS credentials or Terraform installed:

```bash
python scripts/benchmark_terraform_corpus.py
python scripts/benchmark_terraform_corpus.py --output reports/terraform-benchmark.json
```

The runner compares expected finding IDs and analysis completeness, and exits non-zero when a case differs. See [the benchmark corpus contract](docs/terraform-benchmark-corpus.md). Export the active rule registry as deterministic JSON for reviews and upstream capability mapping:

```bash
python scripts/export_rule_inventory.py --output reports/rule-inventory.json
```

The [upstream-tool gap analysis](docs/upstream-tool-gap-analysis.md) distinguishes AWS CSPM from IaC scanning and tracks check-by-check mappings without claiming unverified parity.


## Current implementation pull requests

The following reviewable increments are open against `main`. They are not merged and their tests have not been run in the connected environment; run the local test suite and review each scope before merging.

- [#236 — bounded Security Hub control finding ingestion](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/236), addressing [#113](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/113). Additive fetch helper with pagination bounds, deduplication and truncation metadata; CLI integration remains follow-up work.
- [#237 — bounded GuardDuty regional finding ingestion](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/237), addressing [#114](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/114). Additive regional fetch helpers with filters and completeness metadata; CLI integration remains follow-up work.
- [#238 — controlled live AWS validation evidence matrix](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/238), addressing [#121](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/121). Documents a manual, read-only validation process and service-domain evidence checklist.
- [#239 — conservative Terraform static reference resolver](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/239), addressing [#172](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/172). Adds a bounded static-resolution primitive; HCL pipeline integration remains follow-up work.
- [#240 — opt-in bounded pinned GitHub module fetching](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/240), addressing [#174](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/174). Supports allowlisted pinned GitHub root modules only; Registry downloads and CLI integration remain follow-up work.


## Current implementation batch (22 October 2026)

The following focused pull requests are open for review. They are incremental implementation work, not yet merged or locally test-verified. Several introduce reusable primitives that still need integration into the main scan orchestration; the PR descriptions identify those boundaries.

- [#242 — rule inventory drift check](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/242), for [issue #234](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/234). Checks registry ID uniqueness and the README's total registered-rule count.
- [#243 — IAM policy structural analysis](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/243), for [issue #227](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/227). Models supported statement fields and explicit unknown/incomplete semantics; existing rules are not yet wired to consume it.
- [#244 — evidence-bounded network relationship analysis](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/244), for [issue #228](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/228). Builds a provenance-aware relationship graph and avoids claiming reachability from incomplete evidence.
- [#245 — enabled-region scope planner](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/245), for [issue #229](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/229). Adds deterministic region selection and bounded enabled-region enumeration; CLI integration remains outstanding.
- [#246 — data and analytics service discovery helpers](https://github.com/ledgejigsaw/AWS-Security-Scanner/pull/246), for [issue #230](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/230). Adds metadata-only collectors for OpenSearch, Redshift, ElastiCache, MSK and AWS Backup; provider orchestration and service-specific rules remain outstanding.
