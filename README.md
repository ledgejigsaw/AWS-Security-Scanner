# AWS Security Scanner

A Python-based **AWS Cloud Security Posture Management (CSPM)** tool designed to identify common AWS security misconfigurations across **AWS configuration, Terraform Infrastructure as Code (IaC), and controlled security fixtures**.

The project is being developed as a practical cloud-security engineering portfolio project, with an emphasis on:

* Security by design
* Least privilege
* Modular architecture
* Automated security testing
* Infrastructure as Code security
* Reusable security rules
* Separation of security logic from configuration sources
* Extensible provider architecture
* Evidence-based security findings
* Deterministic security analysis
* Read-only security assessment

The long-term objective is to provide a **read-only security assessment capability** for AWS environments and Infrastructure as Code, with the ability to identify security issues before infrastructure is deployed.

---

# Project Status

**Current version: `0.1.0`**

The project is currently in active development.

The core security-analysis architecture is now implemented and tested using local security fixtures and Terraform JSON configuration.

The current implementation includes:

* Normalised security resource model
* Fixture-based configuration provider
* Terraform JSON provider
* Terraform resource relationship resolution
* Terraform S3 resource aggregation
* Modular security rules
* Resource-aware rule execution
* Centralised rule registry
* Rule metadata
* Standardised security findings
* S3 security controls
* IAM security controls
* JSON reporting
* Command-line scanning
* Unit testing
* Integration testing

### Current Test Status

```text
83 passed
```

All current automated tests pass.

The project does **not yet perform live AWS account scanning**.

AWS API integration is being deliberately deferred until the underlying resource, rule, finding and reporting architecture has matured sufficiently.

This approach allows security-analysis functionality to be developed and tested without requiring live AWS infrastructure or credentials.

---

# Current Capability

| Capability                         | Status      |
| ---------------------------------- | ----------- |
| Python package structure           | Implemented |
| Normalised `Resource` model        | Implemented |
| Fixture provider                   | Implemented |
| Terraform JSON provider            | Implemented |
| Terraform resource discovery       | Implemented |
| Terraform relationship resolution  | Implemented |
| Terraform S3 aggregation           | Implemented |
| Resource-aware rule engine         | Implemented |
| Central rule registry              | Implemented |
| `@rule_for()` decorator            | Implemented |
| Rule metadata model                | Implemented |
| Standardised `Finding` model       | Implemented |
| `Finding.from_rule()` construction | Implemented |
| S3 security controls               | Implemented |
| IAM security controls              | Implemented |
| JSON reporting                     | Implemented |
| Command-line interface             | Implemented |
| Unit testing                       | Implemented |
| Integration testing                | Implemented |
| Live AWS provider                  | Planned     |
| Direct Terraform HCL parsing       | Planned     |
| Additional Terraform normalisation | In progress |
| CI/CD integration                  | Planned     |
| HTML reporting                     | Planned     |
| Compliance mapping                 | Planned     |

---

# Implemented Security Controls

The current implementation contains **10 security controls** covering S3 and IAM.

| Check ID | Service | Security Check                           | Severity | Status      |
| -------- | ------- | ---------------------------------------- | -------- | ----------- |
| S3-001   | S3      | Publicly accessible bucket               | CRITICAL | Implemented |
| S3-002   | S3      | Server-side encryption disabled          | HIGH     | Implemented |
| S3-003   | S3      | Bucket versioning disabled               | MEDIUM   | Implemented |
| S3-004   | S3      | Block Public Access disabled             | HIGH     | Implemented |
| S3-005   | S3      | Server access logging disabled           | MEDIUM   | Implemented |
| S3-006   | S3      | Wildcard bucket policy principal         | HIGH     | Implemented |
| IAM-001  | IAM     | Unrestricted `Action=*` and `Resource=*` | CRITICAL | Implemented |
| IAM-002  | IAM     | Wildcard IAM permissions                 | HIGH     | Implemented |
| IAM-003  | IAM     | Excessive administrative permissions     | HIGH     | Implemented |
| IAM-004  | IAM     | Insecure IAM role trust policy           | HIGH     | Implemented |

Additional security controls will be added as support for further AWS services and resource types is developed.

---

# Architecture

The scanner uses a **provider → resource → rule engine → finding → reporting** architecture.

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
                    | Resource Filtering|
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

The architecture deliberately separates:

1. **Configuration acquisition**
2. **Resource normalisation**
3. **Security analysis**
4. **Finding construction**
5. **Reporting**

Security rules should not depend directly on AWS SDK responses, Terraform syntax or fixture-specific structures.

Instead, providers convert source-specific configuration into a common `Resource` representation.

---

# Configuration Providers

The project uses a provider architecture so that configuration can be obtained from different sources.

Current providers:

```text
FixtureProvider
TerraformProvider
```

An AWS provider is represented within the project architecture, but live AWS discovery is **not yet implemented**.

The intended architecture is:

```text
Fixture ────────┐
                |
Terraform ──────┼──> Provider ──> Resource
                |
AWS API ────────┘
```

This allows security rules to remain independent from the mechanism used to obtain configuration.

---

# Normalised Resource Model

The `Resource` model acts as the common interface between configuration providers and security rules.

The model currently represents information such as:

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

The security rules therefore do not need to know whether a resource originated from:

* A local fixture
* Terraform
* The AWS API

This is a core architectural principle of the project.

---

# Terraform Resource Relationships

Terraform can represent a single logical AWS resource using multiple Terraform resources.

For example, an S3 bucket may be represented by:

```text
aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_server_side_encryption_configuration
```

The Terraform provider identifies references between these resources.

Example:

```text
aws_s3_bucket_versioning.company_data
             |
             | bucket =
             v
aws_s3_bucket.company_data
```

These relationships are represented within the normalised resource model.

The normalisation layer can then aggregate related Terraform resources into a logical security resource.

Example:

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

This allows security rules to analyse the **logical AWS configuration** rather than needing to understand Terraform's resource decomposition.

---

# Rule Architecture

Security rules declare the resource type they apply to using the `@rule_for()` decorator.

Example:

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

The decorator associates a rule with:

* Resource type
* Check ID
* Service
* Severity
* Category
* Title
* Description
* Remediation

The rule engine then executes only rules applicable to the resource being evaluated.

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

This provides a scalable foundation for supporting additional AWS resource types.

---

# Rule Registry

Security rules are maintained through a central rule registry.

Current controls:

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

The registry provides the active security control set to the rule engine.

Additional services can be introduced without redesigning the core rule engine.

---

# S3 Security Controls

## S3-001 — Publicly Accessible Bucket

**Severity:** `CRITICAL`

Detects an S3 bucket configured for public access.

The resulting finding contains structured information including:

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

---

## S3-002 — Server-Side Encryption Disabled

**Severity:** `HIGH`

Detects S3 buckets where server-side encryption is disabled.

The current implementation supports the security representation used by the fixture provider and Terraform normalisation layer.

---

## S3-003 — Bucket Versioning Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where versioning is disabled.

Terraform S3 versioning configuration can be associated with the logical S3 bucket during normalisation.

---

## S3-004 — Block Public Access Disabled

**Severity:** `HIGH`

Detects S3 buckets where Block Public Access is disabled.

The current implementation uses the project's normalised configuration representation.

More complete AWS API modelling is planned as part of the AWS provider.

---

## S3-005 — Server Access Logging Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where server access logging is disabled.

Appropriate access logging improves visibility during monitoring and security investigations.

---

## S3-006 — Wildcard Bucket Policy Principal

**Severity:** `HIGH`

Detects bucket-policy statements containing an `Allow` effect with a wildcard principal.

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

## IAM-001 — Unrestricted IAM Permissions

**Severity:** `CRITICAL`

Detects IAM policy statements containing:

```text
Effect   = Allow
Action   = *
Resource = *
```

This combination represents unrestricted permissions.

---

## IAM-002 — Wildcard IAM Permissions

**Severity:** `HIGH`

Detects wildcard IAM permissions including:

```text
Action   = *
Resource = *
```

and service-wide wildcard actions such as:

```text
s3:*
```

The rule distinguishes fully unrestricted permissions from individual wildcard permissions to avoid duplicating IAM-001 findings.

---

## IAM-003 — Excessive Administrative Permissions

**Severity:** `HIGH`

Detects selected high-risk IAM administrative actions, including:

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

These permissions may contribute to privilege escalation or excessive administrative capability.

---

## IAM-004 — Insecure IAM Role Trust Policy

**Severity:** `HIGH`

Detects IAM role trust policies that allow role assumption by wildcard principals.

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

# Security Finding Model

Security findings use a consistent model containing:

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

Rule metadata is declared through `@rule_for()` and findings are constructed using `Finding.from_rule()`.

This provides a standard interface between security analysis and reporting.

The model is designed to support future consumers such as:

* Terminal output
* JSON reports
* HTML reports
* CI/CD pipelines
* Security dashboards
* Risk-scoring systems

---

# JSON Reporting

The current implementation supports structured JSON reporting.

Reports contain a structure similar to:

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

The reporting layer is separated from the rule engine so additional reporting formats can be introduced without modifying security-analysis logic.

---

# Command-Line Interface

The scanner provides a command-line interface for supported configuration sources.

Example Terraform JSON scan:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

Current CLI capabilities include:

* Fixture-based scanning
* Terraform JSON scanning
* JSON report generation
* Configurable report output

The CLI currently operates against local configuration and does not require AWS credentials.

---

# Infrastructure as Code

Terraform is being developed as a first-class configuration source.

The current implementation supports **Terraform JSON configuration**.

It can:

* Discover Terraform resources
* Create normalised `Resource` objects
* Resolve Terraform resource references
* Identify relationships between resources
* Aggregate related S3 configuration

The current Terraform work should be understood as **configuration ingestion and normalisation**, rather than complete Terraform security scanning.

Direct Terraform HCL parsing remains a future task.

The intended architecture is:

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

The longer-term objective is to identify security issues **before infrastructure is deployed**.

---

# Testing

The project uses `pytest` for automated unit and integration testing.

Run the complete test suite:

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
* Reporting behaviour
* CLI behaviour

The tests are deliberately designed to operate without live AWS infrastructure.

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

# Security Design

The project follows a modular, rule-based security architecture.

## Separation of Concerns

Each component has a defined responsibility:

```text
Provider
   ↓
Configuration acquisition

Normalisation
   ↓
Logical resource reconstruction

Rule Engine
   ↓
Rule selection and execution

Security Rules
   ↓
Security assessment

Finding Model
   ↓
Standardised security result

Reporting
   ↓
Output
```

This prevents cloud-provider API logic and Terraform syntax from becoming tightly coupled to security-analysis logic.

## Testability

Security rules can be tested without:

* AWS credentials
* Live AWS accounts
* Live infrastructure

Known-good and known-bad configurations are represented using controlled fixtures.

This provides:

* Deterministic test conditions
* Fast feedback
* Reproducible results
* Regression protection

## Read-Only Design

The scanner is intended to assess infrastructure rather than modify it.

The eventual AWS integration will use read-only permissions wherever practical.

## Least Privilege

The eventual AWS integration should use only the permissions required to perform security assessment.

## Evidence-Based Findings

Security findings should identify the configuration that caused the finding.

This provides useful information for:

* Investigation
* Remediation
* Reporting
* CI/CD integration

## Deterministic Analysis

Given the same configuration, security rules should produce predictable results.

This is particularly important for Infrastructure as Code and automated security gates.

## Extensibility

Additional services can be introduced by adding the required:

```text
Resource model support
        +
Provider support
        +
Normalisation logic
        +
Security rules
        +
Tests
```

The core rule engine does not need to be redesigned for each new AWS service.

---

# Security Philosophy

The project is built around the following principles.

### Read-Only by Design

The scanner assesses configuration rather than modifying infrastructure.

### Least Privilege

AWS access should be restricted to the minimum permissions required for assessment.

### Evidence-Based Findings

Findings should provide evidence explaining why a control failed.

### Deterministic Security Rules

Security checks should produce predictable results from a given configuration.

### Automated Testing

Security controls should be supported by automated tests.

### Separation of Security Logic

Rules should remain independent of AWS API and Terraform implementation details.

### Resource-Aware Analysis

Rules should execute only against resource types for which they are designed.

---

# Development Approach

Security controls are developed incrementally using a test-driven development workflow.

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

The development process follows:

```text
RED → GREEN → REFACTOR
```

1. Define the required security behaviour.
2. Write a test representing that behaviour.
3. Confirm the test fails for the expected reason.
4. Implement the minimum required functionality.
5. Confirm the test passes.
6. Refactor where appropriate.
7. Run the complete regression suite.
8. Commit the completed change.

Architectural changes are also validated through automated unit and integration tests.

Controlled fixtures are used before live AWS integration so security-analysis functionality can be validated independently of cloud credentials.

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

## Phase 2 — S3 Security

* [x] S3-001 — Public bucket detection
* [x] S3-002 — Encryption disabled
* [x] S3-003 — Versioning disabled
* [x] S3-004 — Block Public Access configuration
* [x] S3-005 — Server access logging
* [x] S3-006 — Wildcard bucket-policy principal
* [x] Terraform S3 resource discovery
* [x] Terraform S3 relationship resolution
* [x] Terraform S3 versioning aggregation
* [x] Terraform S3 encryption aggregation
* [ ] Terraform S3 Block Public Access aggregation
* [ ] Terraform S3 logging aggregation
* [ ] Terraform S3 bucket-policy aggregation

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

## Phase 4 — Terraform Security

* [x] Terraform JSON resource discovery
* [x] Terraform resource normalisation
* [x] Terraform resource relationship resolution
* [x] Terraform S3 resource aggregation
* [ ] Direct Terraform/HCL parsing
* [ ] Terraform-specific security fixtures
* [ ] Additional Terraform resource normalisation
* [ ] Pre-deployment security analysis
* [ ] Terraform CI/CD integration

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

## Phase 8 — Reporting

* [ ] Rich terminal reporting
* [x] JSON output
* [ ] HTML reports
* [ ] Severity filtering
* [ ] Risk scoring
* [ ] Evidence presentation
* [ ] CIS AWS Foundations Benchmark mapping
* [ ] NIST mapping

## Phase 9 — DevSecOps

* [ ] GitHub Actions integration
* [ ] Automated security scanning
* [ ] Terraform security gates
* [ ] Pull-request findings
* [ ] CI/CD exit codes based on severity
* [ ] Security regression testing

## Phase 10 — Advanced Features

* [ ] Infrastructure architecture visualisation
* [ ] Historical findings
* [ ] Security posture dashboard
* [ ] Finding trend analysis
* [ ] Resource dependency analysis
* [ ] Attack-path analysis
* [ ] Security posture scoring

---

# Planned Security Framework Mapping

As the scanner matures, security controls may be mapped against established frameworks and benchmarks including:

* CIS AWS Foundations Benchmark
* NIST Cybersecurity Framework
* NIST SP 800-series guidance
* AWS security best practices

Mappings will only be added where an implemented security check has a defensible relationship to the relevant control or recommendation.

---

# Project Goals

The long-term goal is to develop a scanner that is:

* Modular
* Testable
* Extensible
* Read-only
* Evidence-driven
* Infrastructure-as-Code aware
* Suitable for CI/CD integration
* Capable of analysing multiple configuration sources
* Built around reusable security rules

The project is also intended to demonstrate practical capability across:

* AWS security
* Cloud Security Posture Management
* Python software engineering
* Infrastructure as Code
* Terraform
* AWS IAM
* S3 security
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

The project is provided for educational and security-engineering purposes and is not intended to replace a comprehensive commercial cloud-security platform or professional security assessment.

---

# Licence

Licence to be determined.
