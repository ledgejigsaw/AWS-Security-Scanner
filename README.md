# AWS Security Scanner

A Python-based **AWS Cloud Security Posture Management (CSPM)** tool designed to identify common AWS security misconfigurations across cloud configuration, Infrastructure as Code and controlled security fixtures.

The project is being developed as a security engineering portfolio project, with an emphasis on:

* Security-by-design
* Least privilege
* Modular architecture
* Automated testing
* Infrastructure security
* Reusable security rules
* Separation of security logic from configuration sources
* Infrastructure as Code security
* Extensible provider architecture
* Evidence-based security findings
* Deterministic security analysis

The long-term objective is to provide a **read-only security assessment capability** for AWS environments, Terraform infrastructure-as-code and controlled test fixtures.

---

# Project Status

**Current version: 0.1.0**

The project is currently being developed primarily using local security fixtures and Terraform JSON configuration, with structured JSON reporting and a command-line interface now implemented.

This allows the security detection engine and its supporting architecture to be developed and tested without requiring an active AWS account or live cloud infrastructure.

The architecture is designed so that the same security rules can eventually analyse configuration obtained from multiple sources.

### Current test status

```text
83 passed
```

All current automated tests pass.

---

# Current Development State

The project currently contains:

* A normalised security resource model
* Fixture-based configuration discovery
* Terraform JSON resource discovery
* Terraform resource relationship resolution
* Terraform S3 resource aggregation
* Modular security rules
* Resource-aware rule execution
* Centralised rule registration
* Automated unit testing
* Integration testing
* S3 security controls
* IAM security controls
* Rule metadata architecture
* Standardised security findings
* JSON reporting
* Command-line scanning interface

The current architecture separates **configuration acquisition**, **resource normalisation**, **security analysis** and **reporting**.

AWS API integration is intentionally not yet enabled. This allows the security-analysis architecture to mature before introducing live cloud infrastructure and AWS authentication.

---

# Implemented Security Controls

| Check ID | Service | Security Check                           | Severity | Status      |
| -------- | ------- | ---------------------------------------- | -------- | ----------- |
| S3-001   | S3      | Publicly accessible bucket               | CRITICAL | Implemented |
| S3-002   | S3      | Server-side encryption disabled          | HIGH     | Implemented |
| S3-003   | S3      | Bucket versioning disabled               | MEDIUM   | Implemented |
| S3-004   | S3      | Block Public Access disabled             | HIGH     | Implemented |
| S3-005   | S3      | Server access logging disabled           | MEDIUM   | Implemented |
| S3-006   | S3      | Bucket policy allows wildcard principal  | HIGH     | Implemented |
| IAM-001  | IAM     | Unrestricted `Action=*` and `Resource=*` | CRITICAL | Implemented |
| IAM-002  | IAM     | Wildcard IAM permissions                 | HIGH     | Implemented |
| IAM-003  | IAM     | Excessive administrative permissions     | HIGH     | Implemented |
| IAM-004  | IAM     | Insecure IAM role trust policy           | HIGH     | Implemented |

Additional security controls will be added as new AWS services and resource types are introduced.

---

# Architecture

The scanner is built around a separation-of-concerns architecture.

Configuration is obtained from a provider, converted into a normalised `Resource` representation, optionally aggregated where a configuration source represents a logical resource using multiple objects, evaluated by resource-specific security rules and converted into standardised security findings.

```text
                         DATA SOURCES
                              |
              +---------------+---------------+
              |               |               |
          Fixtures        Terraform          AWS
              |               |               |
              v               v               |
       Fixture Provider   Terraform Provider  |
              |               |               |
              +---------------+---------------+
                              |
                              v
                    +-------------------+
                    |   Resource Model  |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |   Normalisation   |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |    Rule Engine    |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Resource-Type     |
                    |    Filtering      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |  Security Rules   |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |     Findings      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |     Reporting     |
                    +-------------------+
```

The separation between configuration sources and security rules is a core architectural principle of the project.

Security rules should not depend directly on AWS SDK responses, Terraform syntax or fixture-specific structures.

Instead, providers are responsible for converting source-specific configuration into the common `Resource` model.

---

# Configuration Providers

The scanner is designed around a provider architecture.

A provider is responsible for discovering configuration from a particular source and converting it into the common resource representation.

Current providers include:

```text
FixtureProvider
TerraformProvider
```

An AWS provider exists within the project architecture but live AWS discovery is planned for a later development phase.

The intended architecture is:

```text
Fixture ────────┐
                |
Terraform ──────┼──> Provider ──> Resource
                |
AWS API ────────┘
```

This allows the security rules to remain independent from the mechanism used to obtain configuration.

---

# Normalised Resource Model

A common `Resource` model sits between configuration providers and security rules.

The current model contains:

```text
resource_type
resource_id
attributes
source
region
relationships
```

Conceptually:

```text
Configuration Source
        |
        v
     Provider
        |
        v
     Resource
        |
        v
 Normalisation
        |
        v
   Rule Engine
        |
        v
 Security Rule
        |
        v
    Finding
```

The security rules should not need to know whether configuration originated from:

* A local JSON fixture
* Terraform
* The AWS API

This allows the security detection engine to be developed and tested independently from cloud-provider APIs.

For example:

```text
Local Fixture ─────┐
                   |
Terraform ─────────┼──> Resource ──> Rule Engine ──> Security Rules
                   |
AWS API ───────────┘
```

This reduces coupling between data acquisition and security analysis while allowing the same security controls to operate across multiple configuration sources.

---

# Resource Relationships

Terraform resources frequently represent a single logical AWS resource using multiple Terraform resources.

For example, an S3 bucket may be represented using separate resources for:

```text
aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_server_side_encryption_configuration
```

The Terraform provider identifies references between these resources.

For example:

```text
aws_s3_bucket_versioning.company_data
             |
             | bucket =
             v
aws_s3_bucket.company_data
```

These relationships are represented in the normalised resource model.

The normalisation layer can then aggregate related Terraform resources into a logical security resource.

For example:

```text
Terraform Resources

aws_s3_bucket.company_data
        +
aws_s3_bucket_versioning.company_data
        +
aws_s3_bucket_server_side_encryption_configuration.company_data

                    |
                    v

          Normalised S3 Resource

          company_data
          ├── bucket
          ├── region
          ├── versioning
          └── encryption
```

This is important because security rules should analyse the **logical security configuration**, rather than needing to understand Terraform's resource decomposition.

---

# Rule Architecture

Security rules declare the AWS resource type they apply to.

Rules use the `@rule_for()` decorator:

```python
@rule_for(
    "aws_s3_bucket",
    check_id="S3-001",
    service="S3",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="S3 bucket is publicly accessible",
    description="...",
    remediation="...",
)
def check_public_bucket(resource: Resource) -> list[Finding]:
    ...
```

The decorator associates a rule with a normalised resource type and structured security metadata.

The rule engine then executes only rules applicable to the resource being evaluated. The metadata is also used to construct consistent `Finding` objects across the rule set.

Conceptually:

```text
Resource
    |
    | resource_type = "aws_s3_bucket"
    v
Rule Engine
    |
    +---- S3 rules       --> Execute
    |
    +---- IAM rules      --> Skip
    |
    +---- EC2 rules      --> Skip
    |
    +---- VPC rules      --> Skip
```

This allows the scanner to support multiple AWS resource types without every rule being executed against every resource.

---

# Rule Registry

Security rules are maintained through a central rule registry.

The registry currently contains the implemented S3 and IAM controls:

```text
Rule Registry
      |
      +---- S3-001
      +---- S3-002
      +---- S3-003
      +---- S3-004
      +---- S3-005
      +---- S3-006
      |
      +---- IAM-001
      +---- IAM-002
      +---- IAM-003
      +---- IAM-004
```

The registry provides the rule engine with the active security control set.

As additional services are introduced, their rules can be added without redesigning the rule engine.

---

# Project Structure

```text
AWS-Security-Scanner/
│
├── policies/
├── reports/
│
├── src/
│   └── aws_security_scanner/
│       │
│       ├── __init__.py
│       ├── cli.py
│       ├── engine.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py
│       │   ├── resource.py
│       │   └── rule.py
│       │
│       ├── providers/
│       │   ├── __init__.py
│       │   ├── aws.py
│       │   ├── fixture.py
│       │   └── terraform.py
│       │
│       ├── normalization/
│       │   ├── __init__.py
│       │   └── terraform.py
│       │
│       ├── reporting/
│       │   └── __init__.py
│       │
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── json_reporter.py
│       │   └── summary.py
│       │
│       └── rules/
│           ├── __init__.py
│           ├── decorators.py
│           ├── registry.py
│           ├── s3_rules.py
│           └── iam_rules.py
│
├── tests/
│   ├── fixtures/
│   │   ├── s3/
│   │   │   ├── insecure_bucket.json
│   │   │   └── secure_bucket.json
│   │   │
│   │   ├── iam/
│   │   │   ├── overly_permissive_policy.json
│   │   │   ├── restricted_policy.json
│   │   │   ├── wildcard_action_policy.json
│   │   │   ├── wildcard_resource_policy.json
│   │   │   └── roles/
│   │   │       ├── insecure_trust_policy.json
│   │   │       └── secure_trust_policy.json
│   │   │
│   │   └── terraform/
│   │       ├── s3_buckets.json
│   │       └── realistic_s3.json
│   │
│   ├── models/
│   │   ├── test_finding.py
│   │   ├── test_resource.py
│   │   └── test_rule.py
│   │
│   ├── normalization/
│   │   └── test_terraform_normalization.py
│   │
│   ├── providers/
│   │   └── test_terraform.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── test_json_reporter.py
│   │   └── test_summary.py
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── test_decorators.py
│   │   ├── test_registry.py
│   │   ├── test_s3_rules.py
│   │   └── test_iam_rules.py
│   │
│   ├── __init__.py
│   ├── test_engine.py
│   ├── test_engine_integration.py
│   └── test_terraform_integration.py
│
├── .gitignore
├── pyproject.toml
└── README.md
```

---

# Installation

## Requirements

* Python 3.11+
* Git
* `pip`
* Python virtual environment

The current fixture and Terraform-based implementation does **not** require an AWS account or AWS credentials.

---

## Clone the Repository

```bash
git clone https://github.com/ledgejigsaw/AWS-Security-Scanner.git
cd AWS-Security-Scanner
```

---

## Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install the Project

```bash
pip install -e .
```

Install development dependencies:

```bash
pip install -e ".[dev]"
```

---

# Testing

The project uses `pytest` for automated security-rule, normalisation, provider, reporting and architecture testing.

Run the complete test suite with:

```bash
pytest -v
```

Current result:

```text
83 passed
```

The test suite covers:

* Security-rule behaviour
* Known-good configurations
* Known-bad configurations
* Resource modelling
* Resource relationships
* Rule metadata
* Rule registration
* Rule-engine behaviour
* S3 integration
* IAM integration
* Terraform resource discovery
* Terraform relationship resolution
* Terraform S3 normalisation
* Terraform S3 encryption aggregation

The tests are deliberately designed to run without live AWS infrastructure.

---

# S3 Security Controls

The scanner currently implements six S3 security controls.

## S3-001 — Publicly Accessible Bucket

**Severity:** `CRITICAL`

Detects an S3 bucket configured for public access.

The rule identifies publicly accessible buckets and generates an evidence-based security finding containing:

```text
Check ID
Severity
Service
Resource
Title
Description
Remediation
Region
Evidence
```

Public object storage can represent a significant data-exposure risk, particularly where buckets contain sensitive, confidential or regulated information.

---

## S3-002 — Server-Side Encryption Disabled

**Severity:** `HIGH`

Detects S3 buckets where server-side encryption is disabled.

The scanner supports the current fixture representation and Terraform normalisation architecture for evaluating encryption configuration.

The rule recommends enabling server-side encryption using an appropriate AWS encryption mechanism according to organisational requirements.

---

## S3-003 — Bucket Versioning Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where versioning is disabled.

Versioning can provide additional protection against accidental deletion or overwriting of objects and improve recovery capabilities.

Terraform S3 versioning configuration can be aggregated into the logical S3 bucket resource during normalisation.

---

## S3-004 — Block Public Access Disabled

**Severity:** `HIGH`

Detects S3 buckets where Block Public Access is disabled.

The current fixture representation uses a simplified configuration model.

The AWS provider will eventually model the underlying S3 Block Public Access configuration more accurately.

---

## S3-005 — Server Access Logging Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where server access logging is disabled.

Without appropriate access logging, visibility into bucket access activity is reduced, which can make security investigations and monitoring more difficult.

---

## S3-006 — Wildcard Bucket Policy Principal

**Severity:** `HIGH`

Detects S3 bucket policies containing an `Allow` statement with a wildcard principal.

Example:

```json
{
    "Effect": "Allow",
    "Principal": "*"
}
```

The rule recommends restricting access to the specific AWS accounts, roles or services that require access.

Both single-statement and multi-statement bucket policies are supported.

---

# IAM Security Controls

The scanner currently implements four initial IAM security controls.

## IAM-001 — Unrestricted IAM Permissions

**Severity:** `CRITICAL`

Detects IAM policy statements containing:

```text
Effect = Allow
Action = *
Resource = *
```

This combination represents unrestricted permissions and can provide complete control over AWS resources available to the affected identity.

---

## IAM-002 — Wildcard IAM Permissions

**Severity:** `HIGH`

Detects wildcard IAM permissions including:

```text
Action = *
Resource = *
```

and service-wide wildcard actions such as:

```text
s3:*
```

The rule distinguishes fully unrestricted permissions from individual wildcard permissions to avoid duplicating the IAM-001 finding.

---

## IAM-003 — Excessive Administrative Permissions

**Severity:** `HIGH`

Detects selected high-risk IAM administrative actions including permissions such as:

```text
iam:CreateUser
iam:CreateRole
iam:AttachRolePolicy
iam:AttachUserPolicy
iam:PutUserPolicy
iam:PutRolePolicy
iam:PassRole
iam:CreateAccessKey
iam:UpdateAssumeRolePolicy
```

The control is intended to identify potentially dangerous administrative capabilities that may contribute to privilege escalation or excessive permissions.

---

## IAM-004 — Insecure IAM Role Trust Policy

**Severity:** `HIGH`

Detects IAM role trust policies that allow role assumption by a wildcard principal.

Example:

```json
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "sts:AssumeRole"
}
```

The rule also evaluates wildcard AWS and federated principals.

Restricted service principals such as:

```json
{
    "Service": "ec2.amazonaws.com"
}
```

do not trigger the finding.

---

# Command-Line Interface

The scanner provides a command-line interface for running assessments against supported configuration sources.

For example, a Terraform JSON scan can be executed with:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

The CLI currently supports:

* Fixture-based scanning
* Terraform JSON scanning
* JSON report generation
* Configurable report output paths

Example output:

```text
Security scan complete. 5 findings written to reports/scan.json
```

The CLI is intentionally read-only and currently operates against local fixtures and Terraform JSON rather than live AWS environments.

---

# Security Finding Model

Security findings use a consistent data model.

A finding currently contains:

```text
Check ID
Severity
Service
Resource
Title
Description
Remediation
Region
Evidence
```

This provides a standard interface for security checks and reporting.

Rules declare their metadata through the `@rule_for()` decorator, and findings are created through `Finding.from_rule()`. This keeps identifiers, severity, service, titles, descriptions and remediation guidance consistent across the rule set.

The findings model is designed so results can be consumed by:

* Terminal reporting
* JSON reports
* HTML reports
* CI/CD pipelines
* Security dashboards
* Risk-scoring systems

---

# JSON Reporting

The scanner currently supports structured JSON output.

A generated report contains:

```text
summary
├── total_findings
└── by_severity

findings
├── check_id
├── severity
├── service
├── resource
├── title
├── description
├── remediation
├── region
└── evidence
```

Reports can be written to a configurable output path using the CLI.

The reporting layer is deliberately separated from the rule engine so additional output formats can be introduced without changing security-analysis logic.

---

# Security Design

The project intentionally uses a modular, rule-based architecture.

Security checks are implemented independently from the mechanism used to obtain cloud configuration data.

## Testability

Security rules can be unit tested without requiring AWS credentials or live infrastructure.

Known-good and known-bad configurations are represented as controlled fixtures.

This provides deterministic test conditions and reduces the risk of regressions.

## Separation of Concerns

The provider is responsible for obtaining and initially normalising configuration.

The Terraform normalisation layer is responsible for reconstructing logical resources where Terraform represents them using multiple resource types.

The security rule is responsible for determining whether the resulting configuration violates a security requirement.

The rule engine determines which rules apply to each resource.

Reporting is responsible for presenting the resulting findings.

This prevents cloud-provider API logic from becoming tightly coupled to security-analysis logic.

## Reusability

Security rules are designed to operate against the common `Resource` model regardless of whether configuration originates from:

```text
Fixture
Terraform
AWS API
```

## Controlled Development

Security checks can be developed and validated locally before introducing live AWS API integration.

This reduces the need to develop and test security functionality directly against live infrastructure.

## Extensibility

Additional providers and security rules can be introduced without redesigning the entire scanner.

The `@rule_for()` decorator provides a consistent mechanism for associating security rules with resource types.

---

# Security Philosophy

The project is being developed around the following principles.

### Read-Only by Design

The scanner is intended to assess cloud configuration rather than modify infrastructure.

The eventual AWS implementation will use read-only permissions wherever practical.

### Least Privilege

The eventual AWS integration should use the minimum permissions required to perform security assessment activities.

### Evidence-Based Findings

Security findings should identify the configuration that caused the finding rather than simply reporting that a check failed.

### Deterministic Security Rules

Where possible, rules should produce deterministic results from a given configuration.

### Automated Testing

Security logic should be covered by automated tests using known-good and known-bad configurations.

### Separation of Security Logic

Security rules should remain independent from AWS API implementation details and Terraform syntax.

### Resource-Aware Analysis

Rules should only execute against resource types for which they are designed.

This provides a scalable foundation for multi-service analysis.

---

# Infrastructure as Code

Terraform is being developed as a first-class configuration source for the scanner.

The current implementation accepts **Terraform JSON configuration** and can:

* Discover Terraform resources
* Create normalised `Resource` objects
* Resolve Terraform resource references
* Identify relationships between resources
* Aggregate related S3 configuration

The current architecture is:

```text
Terraform JSON
      |
      v
Terraform Provider
      |
      v
Resource Model
      |
      v
Relationship Resolution
      |
      v
Terraform Normalisation
      |
      v
Rule Engine
      |
      v
Security Rules
      |
      v
Findings
```

Direct Terraform HCL parsing remains a future development task.

The longer-term objective is to allow security issues to be identified before infrastructure is deployed.

The intended DevSecOps workflow is:

```text
Developer
    |
    v
Terraform Code
    |
    v
AWS Security Scanner
    |
    +----> Security Finding
    |
    +----> Pass
    |
    v
Terraform Deployment
```

This creates the potential for the scanner to operate as a security gate within Infrastructure as Code workflows.

---

# Roadmap

## Phase 1 — Foundation

* [x] Python package structure
* [x] Finding data model
* [x] Normalised resource model
* [x] Resource relationships
* [x] Fixture-based testing
* [x] Fixture provider
* [x] Modular security rules
* [x] Resource-aware rule engine
* [x] Rule registry
* [x] `@rule_for()` resource-type decorator
* [x] Rule metadata model
* [x] Standardised finding construction
* [x] Automated tests
* [x] Engine integration testing
* [x] JSON reporting
* [x] Command-line interface

---

## Phase 2 — S3 Security

* [x] S3-001 — Public bucket detection
* [x] S3-002 — Encryption disabled
* [x] S3-003 — Versioning disabled
* [x] S3-004 — S3 Block Public Access configuration
* [x] S3-005 — Server access logging
* [x] S3-006 — Wildcard bucket-policy principal
* [x] Terraform S3 resource discovery
* [x] Terraform S3 relationship resolution
* [x] Terraform S3 versioning aggregation
* [x] Terraform S3 encryption aggregation
* [ ] Terraform S3 Block Public Access aggregation
* [ ] Terraform S3 logging aggregation
* [ ] Terraform S3 bucket-policy aggregation

---

## Phase 3 — IAM Security

* [x] IAM resource fixtures
* [x] IAM-001 — Unrestricted IAM permissions
* [x] IAM-002 — Wildcard permissions
* [x] IAM-003 — Excessive administrative permissions
* [x] IAM-004 — Insecure trust policies
* [ ] Cross-account access analysis
* [ ] IAM privilege-escalation path analysis
* [ ] MFA assessment
* [ ] Access-key assessment
* [ ] Additional IAM automated tests
* [ ] Terraform IAM normalisation

---

## Phase 4 — Terraform Security

* [x] Terraform JSON resource discovery
* [x] Terraform resource normalisation
* [x] Terraform resource relationship resolution
* [x] Terraform S3 resource aggregation
* [ ] Direct Terraform/HCL parsing
* [ ] Terraform security scanning
* [ ] Terraform-specific security fixtures
* [ ] Additional Terraform resource normalisation
* [ ] Detection of security misconfigurations before deployment
* [ ] Terraform CI/CD integration

---

## Phase 5 — Compute Security

* [ ] EC2 resource model
* [ ] EC2 public exposure
* [ ] IMDSv2 enforcement
* [ ] Public security groups
* [ ] Unencrypted EBS volumes
* [ ] Public AMIs
* [ ] Public snapshots
* [ ] EC2 automated tests
* [ ] Terraform EC2 normalisation

---

## Phase 6 — Network Security

* [ ] VPC resource model
* [ ] VPC configuration
* [ ] Internet gateways
* [ ] Route tables
* [ ] Security groups
* [ ] Network ACLs
* [ ] Public subnets
* [ ] Unnecessary internet exposure
* [ ] Network segmentation checks
* [ ] Network security fixtures and tests
* [ ] Terraform network-resource normalisation

---

## Phase 7 — AWS Integration

* [ ] AWS/Boto3 provider
* [ ] AWS CLI/profile support
* [ ] AWS resource discovery
* [ ] Multi-region scanning
* [ ] Read-only scanner role
* [ ] Multi-account support
* [ ] AWS authentication validation
* [ ] AWS API error handling
* [ ] Rate-limit handling

---

## Phase 8 — Reporting

* [ ] Rich terminal reporting
* [x] JSON output
* [ ] HTML reports
* [ ] Severity filtering
* [ ] Risk scoring
* [ ] Evidence presentation
* [ ] CIS AWS Foundations Benchmark mapping
* [ ] NIST mapping

---

## Phase 9 — DevSecOps

* [ ] GitHub Actions integration
* [ ] Automated security scanning
* [ ] Terraform security gates
* [ ] Pull-request findings
* [ ] CI/CD exit codes based on severity
* [ ] Security regression testing

---

## Phase 10 — Advanced Features

* [ ] Infrastructure architecture visualisation
* [ ] Historical findings
* [ ] Security posture dashboard
* [ ] Finding trend analysis
* [ ] Resource dependency analysis
* [ ] Attack-path analysis
* [ ] Security posture scoring

---

# Development Approach

Each security control is developed incrementally using a test-driven workflow.

```text
Security Requirement
        |
        v
Security Rule Test
        |
        v
Known-Bad Fixture
        |
        v
Known-Good Fixture
        |
        v
Security Rule
        |
        v
Automated Tests
        |
        v
Resource Normalisation
        |
        v
Provider Integration
        |
        v
Reporting
```

The development process follows the:

```text
RED → GREEN → REFACTOR
```

cycle:

1. Write a test representing the required security behaviour.
2. Confirm the test fails for the expected reason.
3. Implement the minimum functionality required.
4. Confirm the test passes.
5. Refactor where appropriate without changing behaviour.
6. Run the complete regression suite.
7. Commit the completed change.

Architectural changes are also validated through automated unit and integration tests.

The project deliberately uses controlled fixtures before introducing live AWS infrastructure. This provides deterministic testing and allows the security-analysis architecture to be validated independently of cloud credentials.

---

# Planned Security Framework Mapping

As the scanner matures, individual security checks may be mapped against established security frameworks and benchmarks, including:

* CIS AWS Foundations Benchmark
* NIST Cybersecurity Framework
* NIST SP 800-series guidance
* AWS security best practices

Mappings will only be added where the implemented security check has a defensible relationship to the relevant control or recommendation.

---

# Project Goals

The primary technical goals are to develop a scanner that is:

* Modular
* Testable
* Extensible
* Read-only
* Evidence-driven
* Infrastructure-as-code aware
* Suitable for CI/CD integration
* Capable of analysing multiple configuration sources
* Designed around reusable security rules

The project is also intended to demonstrate practical understanding of:

* AWS security
* Cloud Security Posture Management (CSPM)
* Python software engineering
* Infrastructure as Code
* Terraform
* AWS IAM
* Network security
* Security automation
* DevSecOps
* Automated security testing
* Test-driven development
* Cloud security architecture

---

# Disclaimer

This project is intended for authorised security assessment, education and defensive security engineering.

Do not use the scanner against AWS environments without appropriate authorisation.

The project is provided for educational and security-engineering purposes and should not be considered a replacement for a comprehensive commercial cloud security platform or professional security assessment.

---

# Licence

Licence to be determined.
