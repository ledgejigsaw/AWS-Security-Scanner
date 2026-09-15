# AWS Security Scanner

A Python-based AWS cloud security posture assessment tool designed to identify common security misconfigurations across AWS resources.

The project is being developed as a portfolio project alongside my Cybersecurity degree, with a focus on **cloud security, secure-by-design development, least privilege, infrastructure security and automated security testing**.

> **Current status:** Active development
> **Current test suite:** 150 passing tests
> **Current release:** v0.1.0
> **Live AWS scanning:** Planned
> **Terraform/IaC scanning:** Supported

---

## Project Overview

The AWS Security Scanner is designed to analyse AWS security configuration and identify potentially insecure configurations.

The long-term goal is to build a modular security assessment platform capable of analysing:

* AWS resources
* Terraform infrastructure
* Local security fixtures
* IAM policies
* S3 configuration
* Network security
* Identity and access controls
* Infrastructure-as-Code security
* Cloud security posture

The scanner uses a **normalised internal resource model**, allowing security rules to operate independently of the original configuration source.

This means the same security rule can eventually analyse a resource from:

```text
Terraform
   │
   ├── Fixture
   │
   └── AWS API
          │
          ▼
   Normalised Resource
          │
          ▼
      Rule Engine
          │
          ▼
       Findings
          │
          ▼
       Reports
```

---

# Current Capabilities

The scanner currently supports:

* Normalised AWS resource representation
* Local JSON security fixtures
* Terraform JSON analysis
* Terraform resource relationship resolution
* Terraform S3 resource aggregation
* Modular security rules
* Central rule registry
* Decorator-based rule registration
* Structured security findings
* Severity classification
* Evidence attached to findings
* JSON reporting
* CLI execution
* Automated testing
* IAM policy analysis
* IAM role trust policy analysis
* S3 security analysis

The project currently contains **14 security rules** and **150 automated tests**.

---

# Security Rules

## Amazon S3

| Rule   | Severity | Description                                  |
| ------ | -------- | -------------------------------------------- |
| S3-001 | CRITICAL | Public S3 bucket                             |
| S3-002 | HIGH     | Server-side encryption disabled              |
| S3-003 | MEDIUM   | Versioning disabled                          |
| S3-004 | HIGH     | S3 Block Public Access disabled              |
| S3-005 | MEDIUM   | Server access logging disabled               |
| S3-006 | HIGH     | Bucket policy contains wildcard principal    |
| S3-007 | HIGH     | Bucket policy does not enforce TLS           |
| S3-008 | HIGH     | Bucket policy allows unrestricted S3 actions |
| S3-009 | HIGH     | Bucket policy contains wildcard resource     |
| S3-010 | CRITICAL | Bucket policy allows public write access     |

### S3-001 — Public Bucket

Detects S3 buckets configured for public access.

**Severity:** CRITICAL

---

### S3-002 — Encryption Disabled

Detects S3 buckets without server-side encryption configuration.

**Severity:** HIGH

---

### S3-003 — Versioning Disabled

Detects S3 buckets where versioning is not enabled.

**Severity:** MEDIUM

---

### S3-004 — Block Public Access Disabled

Detects S3 buckets where one or more Block Public Access controls are disabled.

**Severity:** HIGH

---

### S3-005 — Server Access Logging Disabled

Detects S3 buckets without server access logging configured.

**Severity:** MEDIUM

---

### S3-006 — Wildcard Bucket Principal

Detects bucket policies containing an `Allow` statement with a wildcard principal.

Example:

```json
{
  "Effect": "Allow",
  "Principal": "*"
}
```

**Severity:** HIGH

---

### S3-007 — TLS Not Enforced

Detects bucket policies that do not explicitly deny requests where:

```text
aws:SecureTransport = false
```

**Severity:** HIGH

---

### S3-008 — Excessive S3 Actions

Detects bucket policies granting:

```text
s3:*
```

**Severity:** HIGH

---

### S3-009 — Wildcard Bucket Resource

Detects bucket policies granting access to:

```text
Resource = "*"
```

**Severity:** HIGH

---

### S3-010 — Public Write Access

Detects anonymous write permissions such as:

```text
s3:PutObject
s3:DeleteObject
s3:PutObjectAcl
```

when combined with a wildcard principal.

**Severity:** CRITICAL

---

# IAM Security Rules

| Rule    | Severity | Description                          |
| ------- | -------- | ------------------------------------ |
| IAM-001 | CRITICAL | Unrestricted IAM permissions         |
| IAM-002 | HIGH     | Excessive wildcard IAM permissions   |
| IAM-003 | HIGH     | High-risk administrative permissions |
| IAM-004 | HIGH     | Wildcard IAM role trust principal    |

---

## IAM-001 — Unrestricted Permissions

Detects IAM policies granting:

```text
Action = "*"
Resource = "*"
```

within an `Allow` statement.

**Severity:** CRITICAL

This represents unrestricted permissions and can significantly increase the impact of a compromised identity.

---

## IAM-002 — Excessive Wildcard Permissions

Detects excessively broad IAM permissions involving:

* `Action = "*"`
* Wildcard action patterns
* Wildcard resources
* Wildcard resources contained within lists
* `NotAction`

For example:

```json
{
  "Effect": "Allow",
  "NotAction": "iam:DeleteUser",
  "Resource": "arn:aws:s3:::company-data/*"
}
```

The scanner treats broad `NotAction` permissions as a security finding because `NotAction` can grant a very large effective permission set.

**Severity:** HIGH

IAM-001 and IAM-002 are deliberately separated so that completely unrestricted:

```text
Action="*"
Resource="*"
```

permissions are reported as **CRITICAL**, while other excessively broad permissions are reported as **HIGH**.

---

## IAM-003 — High-Risk Administrative Permissions

Detects selected high-risk IAM permissions including:

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

**Severity:** HIGH

These permissions can potentially allow an identity to create credentials, modify IAM configuration, alter trust relationships or delegate permissions.

---

## IAM-004 — Insecure Role Trust Policy

Detects IAM role trust policies containing wildcard principals.

Examples include:

```json
"Principal": "*"
```

or:

```json
"Principal": {
  "AWS": "*"
}
```

and:

```json
"Principal": {
  "Federated": "*"
}
```

Supported trust actions include:

```text
sts:AssumeRole
sts:AssumeRoleWithSAML
sts:AssumeRoleWithWebIdentity
```

**Severity:** HIGH

Restricted AWS service principals are not treated as wildcard principals.

---

# Architecture

The project separates configuration sources from security analysis.

```text
                    DATA SOURCES
                         │
             ┌───────────┼───────────┐
             │           │           │
          Fixtures    Terraform      AWS
             │           │           │
             └───────────┼───────────┘
                         │
                         ▼
                NORMALISED RESOURCE
                         │
                         ▼
                    RULE ENGINE
                         │
                         ▼
                      FINDINGS
                         │
                         ▼
                     REPORTING
```

This architecture is intentional.

Security rules should not need to understand whether a resource originated from Terraform, a fixture or the AWS API.

Instead, providers convert their source data into the common `Resource` model.

---

# Normalised Resource Model

Resources are represented internally using a common model:

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

This provides a consistent interface for the rule engine.

For example:

```text
Terraform resource
        │
        ▼
TerraformProvider
        │
        ▼
Resource
        │
        ▼
S3 Security Rules
```

The same S3 rules can eventually operate against:

```text
Terraform → Resource
Fixture   → Resource
AWS API   → Resource
```

without requiring separate implementations of every security check.

---

# Providers

## Fixture Provider

The fixture provider allows security rules to be developed and tested without requiring an active AWS account.

Example fixture:

```json
{
  "resource_type": "aws_s3_bucket",
  "bucket_name": "company-sensitive-data",
  "region": "eu-west-2",
  "public": false,
  "encryption": true,
  "versioning": true
}
```

Fixtures provide deterministic test data and make the project easier to develop offline.

---

## Terraform Provider

Terraform JSON configuration can be analysed and converted into the internal resource model.

The provider also resolves relationships between Terraform resources.

For example:

```text
aws_s3_bucket
       │
       ├── aws_s3_bucket_versioning
       │
       ├── aws_s3_bucket_server_side_encryption_configuration
       │
       ├── aws_s3_bucket_public_access_block
       │
       ├── aws_s3_bucket_logging
       │
       └── aws_s3_bucket_policy
```

These related resources can then be aggregated into the base S3 bucket resource before security rules are executed.

---

# Terraform Relationship Resolution

Terraform resources commonly reference other resources using expressions such as:

```text
${aws_s3_bucket.company_data.id}
```

The provider resolves these references and records relationships in the normalised resource model.

This allows the scanner to understand relationships between resources instead of analysing every Terraform resource in isolation.

---

# Rule Engine

Security rules are registered using decorators.

Example:

```python
@rule_for(
    "aws_s3_bucket",
    check_id="S3-002",
    service="S3",
    severity=Severity.HIGH,
    category="Data Protection",
    title="S3 bucket encryption disabled",
    description="...",
    remediation="...",
)
def check_encryption(resource: Resource) -> list[Finding]:
    ...
```

The decorator registers the rule with the central rule registry.

The engine can then discover and execute applicable rules based on the resource type.

---

# Findings

Security findings contain structured information including:

* Check ID
* Resource
* Region
* Severity
* Service
* Category
* Title
* Description
* Remediation
* Evidence

Example:

```json
{
  "check_id": "S3-002",
  "severity": "HIGH",
  "service": "S3",
  "resource": "company-sensitive-data",
  "region": "eu-west-2",
  "evidence": "encryption=False"
}
```

Evidence is included so that findings can be traced back to the configuration that triggered the security rule.

---

# Reporting

The scanner currently supports JSON reporting.

Example:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

The generated report is written to:

```text
reports/scan.json
```

The report contains:

* Total findings
* Findings by severity
* Individual findings
* Evidence
* Resource information

---

# CLI

The scanner can be executed through the Python module interface.

Example:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

The project is designed so that additional input sources and output formats can be added without significantly changing the rule engine.

---

# Testing

Testing is a major part of the project.

The current test suite contains:

```text
150 passing tests
```

Run the complete test suite with:

```bash
pytest -q
```

Expected result:

```text
150 passed
```

IAM-specific tests can be run with:

```bash
pytest -q tests/rules/test_iam_rules.py
```

Expected result:

```text
39 passed
```

The tests cover:

* Resource models
* Finding models
* Rule metadata
* Rule registration
* Rule execution
* S3 security rules
* IAM security rules
* IAM wildcard permissions
* IAM `NotAction`
* IAM role trust policies
* Terraform normalisation
* Terraform relationships
* Terraform S3 aggregation
* Providers
* Reporting
* CLI behaviour
* Integration workflows

---

# Test-Driven Development

Security rules are developed with tests alongside the implementation.

The development workflow generally follows:

```text
Define security requirement
          │
          ▼
Write failing test
          │
          ▼
Implement security rule
          │
          ▼
Run focused tests
          │
          ▼
Run full regression suite
          │
          ▼
Commit change
```

This helps ensure that new security controls do not silently break existing functionality.

---

# Project Structure

```text
AWS-Security-Scanner/
│
├── policies/
│
├── reports/
│
├── src/
│   └── aws_security_scanner/
│       │
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
│   ├── test_cli.py
│   ├── test_engine.py
│   ├── test_engine_integration.py
│   ├── test_policy.py
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
* **Rich**
* **PyYAML**
* **pytest**
* **Terraform JSON**
* **Git / GitHub**

The local development environment currently uses Python 3.13.

---

# Security Design Principles

The project is being developed around several core principles.

## Least Privilege

Security rules identify excessive permissions and encourage permissions to be restricted to the minimum required.

## Security by Design

Security is considered during architecture and implementation rather than being added after functionality has been built.

## Deterministic Analysis

Fixtures and Terraform analysis provide repeatable input for reliable testing.

## Evidence-Based Findings

Every finding should provide enough evidence to understand why the rule was triggered.

## Separation of Concerns

Providers handle data collection and normalisation.

Rules handle security analysis.

Reporting handles output.

This separation allows the project to evolve without tightly coupling components.

## Extensibility

New AWS services and security controls should be addable without rewriting the existing rule engine.

---

# Current Limitations

The project is still under active development.

Current limitations include:

* Live AWS discovery is not yet implemented
* Direct Terraform HCL parsing is not yet implemented
* AWS authentication and credential handling are not yet integrated into the scanner
* AWS coverage is currently focused primarily on S3 and IAM
* Reporting is currently focused on JSON
* The scanner does not yet provide a complete AWS security posture assessment
* Some security rules use intentionally simplified detection logic while the rule framework is being developed

These limitations are intentional development milestones rather than final design decisions.

---

# Roadmap

## Phase 1 — Core Scanner

* [x] Normalised resource model
* [x] Fixture provider
* [x] Terraform JSON provider
* [x] Terraform relationship resolution
* [x] S3 resource aggregation
* [x] Rule registry
* [x] Rule decorators
* [x] Structured findings
* [x] JSON reporting
* [x] CLI
* [x] Automated test suite

## Phase 2 — S3 Security

* [x] Public bucket detection
* [x] Encryption detection
* [x] Versioning detection
* [x] Block Public Access detection
* [x] Logging detection
* [x] Wildcard principal detection
* [x] TLS enforcement detection
* [x] Excessive S3 actions
* [x] Wildcard bucket resources
* [x] Public write access

## Phase 3 — IAM Security

* [x] Unrestricted IAM permissions
* [x] Wildcard Action detection
* [x] Wildcard Resource detection
* [x] Wildcard Action patterns
* [x] `NotAction` analysis
* [x] High-risk administrative permissions
* [x] IAM role trust policy analysis
* [x] Wildcard AWS principals
* [x] Wildcard federated principals

## Phase 4 — AWS Integration

* [ ] Implement live AWS provider
* [ ] AWS credential/profile handling
* [ ] Read-only AWS discovery
* [ ] AWS account metadata
* [ ] Region discovery
* [ ] S3 API discovery
* [ ] IAM API discovery
* [ ] Least-privilege scanner IAM policy

## Phase 5 — Additional AWS Services

Planned services include:

* [ ] EC2
* [ ] VPC
* [ ] Security Groups
* [ ] EBS
* [ ] RDS
* [ ] CloudTrail
* [ ] KMS
* [ ] Lambda
* [ ] Secrets Manager
* [ ] CloudWatch
* [ ] SNS
* [ ] SQS

## Phase 6 — Infrastructure as Code

* [x] Terraform JSON analysis
* [x] Terraform resource relationships
* [x] Terraform S3 aggregation
* [ ] Direct HCL parsing
* [ ] Terraform module analysis
* [ ] Terraform variable analysis
* [ ] Terraform security recommendations
* [ ] IaC security reporting

## Phase 7 — Reporting

* [x] JSON reporting
* [x] Severity summaries
* [x] Finding evidence
* [ ] HTML reports
* [ ] Executive security summary
* [ ] Compliance mapping
* [ ] SARIF output
* [ ] CI/CD security reporting

## Phase 8 — CI/CD

* [ ] GitHub Actions
* [ ] Automated test execution
* [ ] Coverage reporting
* [ ] Static analysis
* [ ] Dependency scanning
* [ ] Security regression testing
* [ ] Automated release process

---

# Future Architecture

The long-term architecture is intended to support multiple configuration sources and security analysis workflows.

```text
                         ┌───────────────┐
                         │   AWS APIs    │
                         └───────┬───────┘
                                 │
                         ┌───────▼───────┐
                         │ AWS Provider  │
                         └───────┬───────┘
                                 │
┌──────────────┐          ┌──────▼───────┐
│  Terraform   │─────────►│              │
└──────────────┘          │  Normalised  │
                          │   Resource   │
┌──────────────┐          │    Model     │
│   Fixtures   │─────────►│              │
└──────────────┘          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │ Rule Engine  │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │  Findings    │
                          └──────┬───────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                JSON          HTML          SARIF
```

The objective is to make the scanner capable of analysing both **deployed cloud environments** and **infrastructure before deployment**.

---

# Why I Am Building This

This project is being developed as a practical cybersecurity and cloud-security portfolio project.

Rather than simply building a collection of individual security checks, the project is being used to explore:

* Cloud security architecture
* AWS security controls
* IAM security
* Infrastructure as Code security
* Python application architecture
* Security automation
* Test-driven development
* Security findings and evidence
* CI/CD security
* Least-privilege design
* Cloud security engineering

The longer-term objective is to evolve the project from a local security scanner into a more complete **cloud security posture assessment platform**.

---

# Development Environment

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install the project dependencies:

```bash
pip install -e .
```

Run the tests:

```bash
pytest -q
```

---

# Example Workflow

A typical development workflow looks like:

```bash
git pull origin main

source .venv/bin/activate

pytest -q

# Make changes

pytest -q

git status

git add .

git commit -m "description of change"

git push origin main
```
---

# Project Status

The project is currently in **active development**.

The core architecture is established, with:

* A normalised resource model
* Multiple data providers
* A modular rule engine
* S3 security controls
* IAM security controls
* Terraform analysis
* Structured findings
* JSON reporting
* CLI support
* 150 automated tests

The next major architectural milestone is **live AWS integration**, allowing the same security rules currently used against fixtures and Terraform to analyse read-only AWS configuration.

The project will continue to evolve towards a broader cloud security posture assessment platform.
