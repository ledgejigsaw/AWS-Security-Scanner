# AWS Security Scanner

A Python-based cloud security posture assessment tool designed to identify common security weaknesses across AWS resources and Infrastructure as Code.

The project is being developed as a practical cybersecurity and cloud security portfolio project, with an emphasis on:

* Security-by-design
* Least privilege
* Read-only cloud discovery
* Infrastructure as Code security
* Provider-independent security rules
* Evidence-based findings
* Automated testing
* Modular architecture
* Extensibility

The long-term goal is to build a security scanner capable of analysing AWS environments, Terraform configurations and other supported sources using the same security rule engine.

> **Current status:** The scanner currently supports local fixtures, Terraform JSON analysis and a read-only AWS S3 provider foundation. Live AWS scanning is still under development.

> **Current test suite:** 164 passing tests

---

## Project Overview

The scanner separates **resource discovery**, **normalisation**, **security analysis** and **reporting**.

```text
                       DATA SOURCES
                            │
             ┌──────────────┼──────────────┐
             │              │              │
          Fixtures       Terraform         AWS
             │              │              │
             └──────────────┼──────────────┘
                            │
                            ▼
                   NORMALISED RESOURCE
                         MODEL
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

This architecture means that security rules do not need to understand where a resource came from.

For example, an S3 encryption rule can analyse:

* A local security fixture
* A Terraform configuration
* An AWS resource discovered through boto3

using the same internal `Resource` representation.

---

# Current Capabilities

## Resource Discovery

The project currently supports three resource sources.

### Local fixtures

Local JSON fixtures are used for deterministic security testing without requiring an AWS account.

```text
tests/fixtures/
├── s3/
└── iam/
```

Fixtures are converted into the common `Resource` model before being passed to the rule engine.

### Terraform

Terraform JSON output can be analysed without requiring a live AWS environment.

The Terraform provider currently supports:

* Resource discovery
* Resource normalisation
* Terraform resource relationships
* S3 resource aggregation
* Security configuration analysis

Example:

```bash
terraform show -json > terraform.json
```

The resulting JSON can then be scanned by the project.

### AWS

A read-only AWS provider is currently under development using `boto3`.

The current implementation supports S3 discovery and retrieves:

* Bucket information
* Default server-side encryption
* Bucket versioning
* S3 Block Public Access configuration
* Server access logging
* Bucket policies

AWS API calls are currently tested using mocked boto3 clients, allowing development without storing AWS credentials or requiring a live AWS account.

---

# Normalised Resource Model

All providers convert discovered resources into a common `Resource` model.

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

This provides a consistent interface between:

```text
Provider
   ↓
Resource
   ↓
Rule
   ↓
Finding
```

The approach also keeps security rules independent from individual provider implementations.

---

# Security Rules

The project currently contains **14 security rules**.

## Amazon S3

| ID     | Severity | Description                                  |
| ------ | -------- | -------------------------------------------- |
| S3-001 | Critical | Public S3 bucket                             |
| S3-002 | High     | Server-side encryption disabled              |
| S3-003 | Medium   | Bucket versioning disabled                   |
| S3-004 | High     | S3 Block Public Access disabled              |
| S3-005 | Medium   | Server access logging disabled               |
| S3-006 | High     | Wildcard bucket policy principal             |
| S3-007 | High     | Bucket policy does not enforce TLS           |
| S3-008 | High     | Bucket policy allows unrestricted S3 actions |
| S3-009 | High     | Bucket policy uses wildcard resource         |
| S3-010 | Critical | Bucket policy allows public write access     |

## AWS IAM

| ID      | Severity | Description                                                |
| ------- | -------- | ---------------------------------------------------------- |
| IAM-001 | Critical | IAM policy grants unrestricted permissions                 |
| IAM-002 | High     | IAM policy contains excessively broad wildcard permissions |
| IAM-003 | High     | IAM policy grants high-risk administrative permissions     |
| IAM-004 | High     | IAM role trust policy allows wildcard principal            |

The rule engine is designed to allow additional rules to be added without changing the provider architecture.

---

# S3 Security Analysis

The S3 analysis currently covers several common security controls.

### Public access

Detects buckets configured in a way that can expose data publicly.

### Encryption

Checks whether default server-side encryption is configured.

### Versioning

Identifies buckets without versioning enabled.

### Block Public Access

Checks all four S3 Block Public Access settings:

```text
BlockPublicAcls
BlockPublicPolicy
IgnorePublicAcls
RestrictPublicBuckets
```

The scanner considers Block Public Access enabled only when all four controls are enabled.

### Server access logging

Identifies buckets without S3 server access logging.

### Bucket policies

The scanner analyses bucket policies for:

* Wildcard principals
* Missing TLS enforcement
* `s3:*`
* Wildcard resources
* Public write permissions

---

# IAM Security Analysis

IAM analysis currently focuses on excessive permissions and trust relationships.

The scanner detects:

* `Action: "*"`
* Wildcard actions such as `s3:*`
* Wildcard resources
* `NotAction`
* High-risk IAM administrative permissions
* Wildcard IAM role trust principals

The scanner specifically separates unrestricted permissions from broader wildcard permissions.

For example:

```json
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```

is treated as an unrestricted permission set and generates the critical **IAM-001** finding.

Broader wildcard permissions that do not meet the IAM-001 condition are analysed by **IAM-002**.

---

# `NotAction` Analysis

IAM `NotAction` permissions are also analysed.

For example:

```json
{
    "Effect": "Allow",
    "NotAction": "iam:DeleteUser",
    "Resource": "arn:aws:s3:::example-bucket/*"
}
```

The scanner treats broad `NotAction` permissions as a security finding because they can result in a very large effective permission set.

---

# Architecture

The project is structured around clear separation of responsibilities.

```text
src/aws_security_scanner/
│
├── cli.py
├── engine.py
├── policy.py
│
├── models/
│   ├── finding.py
│   ├── resource.py
│   └── rule.py
│
├── providers/
│   ├── aws.py
│   ├── fixture.py
│   └── terraform.py
│
├── normalization/
│   └── terraform.py
│
├── reporting/
│   ├── summary.py
│   └── json_reporter.py
│
└── rules/
    ├── decorators.py
    ├── registry.py
    ├── s3_rules.py
    └── iam_rules.py
```

---

# Providers

Providers are responsible for discovering resources and converting them into the common resource model.

## FixtureProvider

Used for deterministic local testing.

```text
JSON fixture
     ↓
FixtureProvider
     ↓
Resource
```

## TerraformProvider

Used to analyse Terraform JSON output.

```text
Terraform JSON
      ↓
TerraformProvider
      ↓
Resource
      ↓
Relationship resolution
      ↓
S3 aggregation
```

## AWSProvider

Used for read-only AWS discovery.

```text
AWS API
   ↓
boto3
   ↓
AWSProvider
   ↓
Resource
```

The AWS provider currently focuses on S3.

---

# Terraform Resource Relationships

Terraform often represents related configuration as separate resources.

For example:

```text
aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_server_side_encryption_configuration
aws_s3_bucket_public_access_block
aws_s3_bucket_logging
aws_s3_bucket_policy
```

The scanner resolves Terraform references and aggregates the related configuration back onto the base S3 bucket resource.

This allows the security rules to analyse the bucket as a single logical resource.

---

# Rule Engine

Security rules are registered using decorators.

Conceptually:

```python
@rule_for(
    "aws_s3_bucket",
    check_id="S3-002",
    service="S3",
    severity=Severity.HIGH,
    ...
)
def check_encryption(resource: Resource) -> list[Finding]:
    ...
```

The rule engine can then determine which rules apply to a resource based on its resource type.

This provides a central rule registry without requiring the CLI or providers to know about individual security checks.

---

# Findings

Security findings are represented using a common `Finding` model.

A finding contains information such as:

* Check ID
* Severity
* Service
* Resource
* Region
* Evidence
* Description
* Remediation

This allows the same finding structure to be used regardless of whether the resource originated from:

* Fixtures
* Terraform
* AWS

---

# Evidence-Based Findings

The scanner attempts to provide evidence alongside each finding.

For example:

```text
Check: S3-006
Resource: company-data
Evidence: Principal=*
```

This makes findings easier to investigate and gives the scanner more value than simply reporting:

```text
S3 bucket is insecure
```

The intention is for every finding to provide enough context for a security engineer to understand why the control was triggered.

---

# Reporting

The project currently supports JSON reporting.

Example:

```bash
python -m aws_security_scanner.cli \
    --source terraform \
    --file tests/fixtures/terraform/realistic_s3.json \
    --format json
```

Reports are written to:

```text
reports/scan.json
```

The report contains summary information such as:

```json
{
    "summary": {
        "total_findings": 4,
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 1
        }
    }
}
```

Individual findings also contain their associated evidence.

---

# Testing

Testing is a major part of the project.

The current test suite contains:

> **164 passing tests**

The tests cover:

* Resource models
* Finding models
* Rule models
* Rule decorators
* Rule registration
* S3 security rules
* IAM security rules
* IAM `NotAction`
* Terraform normalisation
* Terraform relationships
* Terraform providers
* Fixture providers
* AWS provider
* Reporting
* CLI behaviour
* Integration paths

Run the complete test suite with:

```bash
pytest -q
```

Run only the AWS provider tests with:

```bash
pytest -q tests/providers/test_aws.py
```

The current AWS provider suite contains tests covering:

```text
S3 bucket discovery
S3 encryption
S3 encryption disabled
S3 versioning
S3 versioning disabled
S3 Block Public Access
S3 Block Public Access disabled
S3 server access logging
S3 server access logging disabled
S3 bucket policies
S3 buckets without policies
```

---

# Development Without AWS Credentials

The project is intentionally being developed without requiring a live AWS environment.

AWS API calls are mocked during testing.

For example:

```python
s3_client = Mock()

s3_client.list_buckets.return_value = {
    "Buckets": [
        {"Name": "example-bucket"}
    ]
}
```

This provides several advantages:

* No AWS credentials stored in the repository
* No accidental production changes
* No AWS infrastructure costs
* Deterministic tests
* Repeatable development
* Easier CI/CD integration

The AWS provider is designed to remain **read-only**.

---

# Security Principles

The project follows several security principles.

## Least privilege

The scanner identifies overly broad permissions and encourages specific permissions and resources.

## Read-only discovery

The AWS provider is intended to inspect configuration rather than modify AWS resources.

## No hard-coded credentials

AWS credentials should never be stored in source code, fixtures or configuration committed to Git.

## Provider-independent rules

Security logic should not depend on whether data came from AWS, Terraform or fixtures.

## Evidence-based analysis

Findings should contain evidence supporting the security decision.

## Deterministic testing

Security checks should be reproducible and independently testable.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/ledgejigsaw/AWS-Security-Scanner.git
cd AWS-Security-Scanner
```

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

# Requirements

* Python 3.11+
* boto3
* PyYAML
* Rich
* pytest for development/testing

The project is currently being developed on Python 3.13.

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
│       ├── cli.py
│       ├── engine.py
│       ├── policy.py
│       │
│       ├── models/
│       ├── providers/
│       ├── normalization/
│       ├── reporting/
│       └── rules/
│
├── tests/
│   ├── fixtures/
│   ├── models/
│   ├── normalization/
│   ├── providers/
│   ├── reporting/
│   └── rules/
│
├── .gitignore
├── pyproject.toml
└── README.md
```

---

# Roadmap

The project is still under active development.

## Completed

* [x] Initial Python project structure
* [x] Normalised `Resource` model
* [x] Finding model
* [x] Rule model
* [x] Rule decorator system
* [x] Central rule registry
* [x] Fixture provider
* [x] Terraform JSON provider
* [x] Terraform resource relationship resolution
* [x] Terraform S3 resource aggregation
* [x] S3-001 through S3-010
* [x] IAM-001 through IAM-004
* [x] IAM wildcard permission analysis
* [x] IAM `NotAction` analysis
* [x] JSON reporting
* [x] CLI integration
* [x] Automated test suite
* [x] Read-only AWS provider foundation
* [x] AWS S3 bucket discovery
* [x] AWS S3 encryption discovery
* [x] AWS S3 versioning discovery
* [x] AWS S3 Block Public Access discovery
* [x] AWS S3 logging discovery
* [x] AWS S3 bucket policy discovery
* [x] Mocked AWS provider tests

## In Progress

* [ ] AWS provider → rule engine integration
* [ ] AWS S3 security integration testing
* [ ] AWS IAM provider
* [ ] AWS IAM policy discovery
* [ ] AWS IAM role/trust policy discovery
* [ ] Expanded AWS resource discovery
* [ ] Live AWS scanning
* [ ] Improved reporting

## Planned

* [ ] EC2 security checks
* [ ] VPC/network security checks
* [ ] Security Group analysis
* [ ] CloudTrail analysis
* [ ] KMS analysis
* [ ] RDS security checks
* [ ] Lambda security checks
* [ ] Secrets Manager checks
* [ ] Additional IAM analysis
* [ ] Additional Terraform resource types
* [ ] Direct Terraform HCL parsing
* [ ] HTML reporting
* [ ] CI/CD security scanning
* [ ] GitHub Actions integration
* [ ] Configuration/policy packs
* [ ] Severity filtering
* [ ] Scan baselines
* [ ] Finding suppression
* [ ] SARIF output
* [ ] Architecture visualisation

---

# Future Architecture

The longer-term objective is to evolve the scanner into a broader cloud security analysis platform.

```text
                    ┌─────────────────────┐
                    │      CLI / API      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    Source Manager   │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
     Terraform              AWS API             Fixtures
          │                    │                    │
          └────────────────────┼────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Normalised Resource │
                    │       Model         │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     Rule Engine     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Findings       │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼─────────────┐
                 │             │             │
                 ▼             ▼             ▼
               JSON          HTML          SARIF
```

---

# Why I'm Building This

This project is being developed as a practical exploration of cloud security engineering rather than simply as a collection of security scripts.

The aim is to demonstrate understanding of:

* Python development
* AWS security
* IAM
* S3 security
* Infrastructure as Code
* Terraform
* Cloud security architecture
* Security automation
* API integration
* Software testing
* Secure software design
* CI/CD security
* Security reporting

The architecture is intentionally being developed incrementally, with tests driving the implementation of individual security capabilities.

---

# Project Status

**Current version:** `0.1.0`

**Security rules:** 14

**Automated tests:** 164 passing

**Data sources:**

* Local fixtures
* Terraform JSON
* AWS S3 API foundation

**AWS access:** Read-only provider under development

**Live AWS scanning:** Not yet implemented

**Status:** Active development

---

# Repository

GitHub:

https://github.com/ledgejigsaw/AWS-Security-Scanner

Feedback, suggestions and contributions are welcome.
