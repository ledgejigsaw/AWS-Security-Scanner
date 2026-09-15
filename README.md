# AWS Security Scanner

A Python-based cloud security posture assessment tool for identifying common security misconfigurations across AWS resources.

The project is being developed as a portfolio project alongside my Cybersecurity degree, with a focus on **cloud security, secure software design, Infrastructure as Code (IaC), automated testing and least-privilege security analysis**.

The scanner is designed around a normalised internal resource model so that the same security rules can analyse different configuration sources without coupling the rules to a particular provider or data format.

> **Project status:** Active development
> **Current test suite:** 147 passing tests
> **Current security rules:** 14
> **Current focus:** S3 and IAM security analysis, Terraform integration and rule-engine development

---

## Project Goals

The long-term goal is to develop a modular cloud security scanner capable of analysing AWS environments and Infrastructure as Code for security weaknesses.

The project is being designed around several principles:

* Security by design
* Least privilege
* Evidence-based findings
* Deterministic security analysis
* Modular rule development
* Automated testing
* Infrastructure as Code security
* Provider-independent security rules
* Separation between data collection and security analysis
* Reusable and extensible architecture

The eventual objective is to support both **local/IaC analysis** and **live AWS account assessment**.

---

## Current Architecture

The scanner separates configuration sources from the security rule engine.

```text
                    DATA SOURCES
                         │
          ┌──────────────┼──────────────┐
          │              │              │
       Fixtures       Terraform         AWS
          │              │              │
          └──────────────┼──────────────┘
                         ↓
                 NORMALISED MODEL
                         ↓
                    RULE ENGINE
                         ↓
                     FINDINGS
                         ↓
                    REPORTING
```

### Why use a normalised model?

Different configuration sources represent AWS resources in different ways.

For example:

* Terraform represents infrastructure as configuration.
* AWS APIs return live resource configuration.
* Local fixtures provide controlled test data.

Instead of writing separate security rules for each source, the scanner converts them into a common `Resource` model.

```python
@dataclass
class Resource:
    resource_type: str
    resource_id: str
    attributes: dict[str, Any]
    source: str
    region: str | None = None
    relationships: dict[str, str] | None = None
```

Security rules then operate against this model.

This allows the same rule to be reused across:

```text
Fixture → Resource → Rule
Terraform → Resource → Rule
AWS API → Resource → Rule
```

---

# Current Features

## Normalised Resource Model

AWS resources are represented using a common internal model containing:

* Resource type
* Resource identifier
* Attributes
* Configuration source
* AWS region
* Resource relationships

This provides a consistent interface between providers and the rule engine.

---

## Fixture Provider

The scanner can currently load controlled JSON security fixtures.

Fixtures are useful for:

* Unit testing
* Regression testing
* Developing new security rules
* Testing edge cases
* Developing without requiring an AWS account

Supported fixture resource types currently include:

* `aws_s3_bucket`
* `aws_iam_policy`
* `aws_iam_role`

---

## Terraform Provider

Terraform JSON configuration can be loaded and converted into the normalised resource model.

The Terraform provider currently supports:

* Terraform JSON discovery
* Resource extraction
* Resource relationships
* AWS resource references
* S3 resource aggregation

Example Terraform resources such as:

```text
aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_server_side_encryption_configuration
aws_s3_bucket_public_access_block
aws_s3_bucket_logging
aws_s3_bucket_policy
```

can be associated with their parent S3 bucket.

This allows security rules to analyse the resulting bucket configuration rather than requiring every rule to understand Terraform's resource structure.

---

# Security Rules

The current scanner contains **14 security rules** across S3 and IAM.

## Amazon S3

| Check ID | Severity | Description                                  |
| -------- | -------- | -------------------------------------------- |
| S3-001   | CRITICAL | Public S3 bucket                             |
| S3-002   | HIGH     | Server-side encryption disabled              |
| S3-003   | MEDIUM   | Bucket versioning disabled                   |
| S3-004   | HIGH     | S3 Block Public Access disabled              |
| S3-005   | MEDIUM   | Server access logging disabled               |
| S3-006   | HIGH     | Wildcard bucket policy principal             |
| S3-007   | HIGH     | Bucket policy does not enforce TLS           |
| S3-008   | HIGH     | Bucket policy allows unrestricted S3 actions |
| S3-009   | HIGH     | Bucket policy contains wildcard resource     |
| S3-010   | CRITICAL | Bucket policy allows public write access     |

### S3 security analysis currently includes

* Public bucket detection
* Encryption configuration
* Versioning
* Block Public Access
* Server access logging
* Bucket policy analysis
* Wildcard principals
* Wildcard actions
* Wildcard resources
* Public write permissions
* TLS enforcement using `aws:SecureTransport`

---

## IAM

| Check ID | Severity | Description                              |
| -------- | -------- | ---------------------------------------- |
| IAM-001  | CRITICAL | Unrestricted IAM permissions             |
| IAM-002  | HIGH     | Excessive wildcard IAM permissions       |
| IAM-003  | HIGH     | High-risk administrative IAM permissions |
| IAM-004  | HIGH     | Insecure IAM role trust policy           |

### IAM security analysis currently includes

* `Action: "*"` detection
* Wildcard resources
* Wildcards represented as lists
* Excessively broad IAM permissions
* High-risk IAM administrative actions
* IAM role trust policies
* Wildcard AWS principals
* Wildcard federated principals
* Assume-role trust relationships

The IAM rule engine is also being developed with additional edge-case coverage for different IAM policy structures.

---

# Rule Engine

Security rules are implemented as independent functions and registered centrally.

A rule contains metadata including:

* Check ID
* AWS service
* Severity
* Category
* Description
* Remediation guidance

Example:

```python
@rule_for(
    "aws_s3_bucket",
    check_id="S3-010",
    service="S3",
    severity=Severity.CRITICAL,
    category="Access Control",
    title="S3 bucket policy allows public write access",
)
def check_public_write_access(resource: Resource) -> list[Finding]:
    ...
```

This allows the rule engine to discover and execute applicable rules without tightly coupling the engine to individual checks.

---

# Findings

Security findings are represented using a common `Finding` model.

Each finding contains information such as:

* Check ID
* Severity
* Service
* Resource
* Region
* Description
* Remediation
* Evidence

The scanner therefore produces findings that can be consumed by different reporting formats without requiring the security rules themselves to understand presentation or reporting.

---

# Evidence-Based Findings

The scanner attempts to include evidence explaining why a resource triggered a rule.

For example:

```text
Principal=*, Action=['s3:PutObject']
```

or:

```text
aws:SecureTransport=false deny not found
```

This is intended to make findings more useful for investigation and remediation rather than simply reporting that a resource is "insecure".

---

# Reporting

The scanner currently supports structured JSON reporting.

Example output:

```text
reports/scan.json
```

The JSON report includes summary information such as:

* Total findings
* Findings by severity
* Individual finding details
* Resource information
* Security evidence
* Remediation guidance

The reporting layer is intentionally separated from the rule engine so additional formats can be added later.

---

# CLI

The scanner can currently be executed against Terraform JSON configuration.

Example:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

The resulting report is written to:

```text
reports/scan.json
```

---

# Testing

Testing is a major part of the project.

The scanner currently has:

```text
147 passing tests
```

Tests cover areas including:

* Resource models
* Finding models
* Rule metadata
* Rule registration
* Security rules
* IAM policies
* S3 policies
* Terraform normalisation
* Terraform relationships
* Terraform integration
* Fixture providers
* Reporting
* CLI behaviour
* End-to-end scanning

The project uses `pytest` for automated testing.

Run the complete test suite with:

```bash
pytest -q
```

Current result:

```text
147 passed
```

---

# Example Project Structure

```text
AWS-Security-Scanner/
│
├── policies/
│
├── reports/
│
├── src/
│   └── aws_security_scanner/
│       ├── __init__.py
│       ├── cli.py
│       ├── engine.py
│       ├── policy.py
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
│       │   ├── summary.py
│       │   └── json_reporter.py
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
│   │   ├── iam/
│   │   └── terraform/
│   │
│   ├── models/
│   ├── normalization/
│   ├── providers/
│   ├── reporting/
│   ├── rules/
│   ├── test_engine.py
│   ├── test_engine_integration.py
│   ├── test_policy.py
│   ├── test_cli.py
│   └── test_terraform_integration.py
│
├── .gitignore
├── pyproject.toml
└── README.md
```

---

# Technology Stack

The project currently uses:

* **Python 3.11+**
* **boto3**
* **pytest**
* **pytest-cov**
* **Rich**
* **PyYAML**
* **Terraform JSON configuration**

Python 3.13 is currently used during development.

---

# Security Design Principles

The project is being developed with the following principles in mind.

### Least Privilege

Security checks identify unnecessarily broad permissions and encourage narrowly scoped access.

### Separation of Concerns

Providers are responsible for obtaining configuration.

Rules are responsible for security analysis.

The reporting layer is responsible for presenting findings.

### Deterministic Analysis

Given the same resource configuration, the scanner should produce the same findings.

### Evidence-Based Detection

Findings should contain enough evidence to explain why a security control was triggered.

### Test-Driven Development

New security controls are developed alongside automated tests, including negative tests and edge cases.

### Extensibility

The architecture is intended to allow additional AWS services and security rules to be added without redesigning the entire scanner.

---

# Current Limitations

The project is still under active development.

Currently:

* Live AWS account scanning is not yet implemented.
* Direct HCL parsing is not yet implemented.
* AWS provider functionality is being developed for future live discovery.
* Coverage is currently focused primarily on S3 and IAM.
* The scanner is not intended to replace established cloud security platforms.
* AWS policy semantics contain additional edge cases that still need to be addressed.

The current development approach deliberately prioritises a strong architecture and comprehensive testing before introducing live AWS discovery.

---

# Roadmap

## Phase 1 — Core Architecture

* [x] Normalised resource model
* [x] Provider architecture
* [x] Fixture provider
* [x] Terraform JSON provider
* [x] Terraform relationship resolution
* [x] S3 resource aggregation
* [x] Rule registration
* [x] Finding model
* [x] Reporting framework
* [x] CLI

## Phase 2 — S3 Security

* [x] Public bucket detection
* [x] Encryption checks
* [x] Versioning checks
* [x] Block Public Access checks
* [x] Logging checks
* [x] Wildcard principals
* [x] TLS enforcement
* [x] Wildcard actions
* [x] Wildcard resources
* [x] Public write access

## Phase 3 — IAM Security

* [x] Unrestricted IAM permissions
* [x] Wildcard IAM permissions
* [x] High-risk administrative actions
* [x] IAM trust policy analysis
* [x] Wildcard policy list coverage
* [x] Wildcard resource list coverage
* [ ] `NotAction` analysis
* [ ] `NotResource` analysis
* [ ] Additional IAM policy condition analysis

## Phase 4 — Additional AWS Services

Planned areas include:

* [ ] EC2 security
* [ ] VPC security
* [ ] Security Groups
* [ ] RDS
* [ ] CloudTrail
* [ ] IAM Access Analyzer integration
* [ ] KMS
* [ ] Lambda
* [ ] ECR
* [ ] Secrets Manager

## Phase 5 — Live AWS Discovery

* [ ] AWS credential/profile support
* [ ] Boto3 resource discovery
* [ ] Read-only AWS permissions
* [ ] Multi-region scanning
* [ ] Account-wide scanning
* [ ] Live AWS security assessment

## Phase 6 — CI/CD and IaC Security

* [ ] GitHub Actions
* [ ] Automated security scanning
* [ ] Terraform pipeline integration
* [ ] Pull-request security checks
* [ ] Security findings suitable for CI/CD
* [ ] Policy-as-code integration

## Phase 7 — Reporting and Visualisation

* [ ] HTML reports
* [ ] Improved terminal reporting
* [ ] Risk scoring
* [ ] Finding aggregation
* [ ] Resource relationship visualisation
* [ ] Terraform architecture visualisation

---

# Development Approach

The project is being developed incrementally.

For each security control, the intended workflow is:

```text
Define security requirement
          ↓
Create test
          ↓
Confirm expected failure
          ↓
Implement rule
          ↓
Run focused tests
          ↓
Run complete regression suite
          ↓
Review evidence/remediation
          ↓
Commit changes
```

This approach helps ensure that adding new security controls does not introduce regressions into existing functionality.

---

# Why Build This?

This project is intended to demonstrate practical skills relevant to cloud security engineering, including:

* Python development
* AWS security
* IAM security
* S3 security
* Infrastructure as Code
* Terraform
* Security automation
* Security testing
* Policy analysis
* Software architecture
* CI/CD security
* Secure coding principles
* Cloud security posture management concepts

Rather than building a collection of isolated security scripts, the project is being developed as a reusable security-analysis platform.

---

# Disclaimer

This project is intended for **educational, defensive security and authorised security assessment purposes**.

Only scan AWS accounts, infrastructure and resources that you own or have explicit permission to assess.

---

# Project Status

**Active development**

Current milestone:

```text
14 security rules
147 passing tests
S3 + IAM analysis
Terraform JSON integration
Normalised resource architecture
JSON reporting
CLI scanning
```

Future development will focus on expanding IAM policy analysis, additional AWS services, live AWS discovery and CI/CD integration.
