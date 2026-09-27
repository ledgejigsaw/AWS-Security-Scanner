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
* Configurable security policies

The long-term goal is to build a security scanner capable of analysing AWS environments, Terraform configurations and other supported sources using the same security rule engine.

> **Current status:** The scanner currently supports local fixtures, Terraform JSON analysis and a read-only AWS provider. AWS resources can now flow through the normalised `Resource` model, rule engine, S3 security rules and JSON reporting pipeline. YAML-based policy configuration is also supported.

> **Current test suite:** 168 passing tests

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

The AWS provider therefore does not contain the security logic itself. It is responsible for discovery and normalisation, while the rule engine remains responsible for security analysis.

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

Terraform resources such as:

```text
aws_s3_bucket
aws_s3_bucket_versioning
aws_s3_bucket_server_side_encryption_configuration
aws_s3_bucket_public_access_block
aws_s3_bucket_logging
aws_s3_bucket_policy
```

can be resolved and aggregated into the logical S3 bucket representation used by the security rules.

### AWS

A read-only AWS provider has now been implemented using `boto3`.

The current implementation supports S3 discovery and retrieves:

* Bucket information
* Default server-side encryption
* Bucket versioning
* S3 Block Public Access configuration
* Server access logging
* Bucket policies

The AWS discovery path is integrated with the scanner's normalised resource model and rule engine:

```text
AWS API
   ↓
AWSProvider
   ↓
Resource
   ↓
RuleEngine
   ↓
S3 Security Rules
   ↓
Findings
   ↓
JSON Reporting
```

AWS API calls are tested using mocked boto3 clients, allowing development and testing without storing AWS credentials in the repository.

The AWS provider is intentionally read-only.

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

A resource discovered through AWS can therefore be analysed by the same rule implementation used for a Terraform resource or local fixture.

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

The same S3 security rules can be applied to resources originating from fixtures, Terraform or the AWS provider.

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

This provides coverage for a policy construct that can otherwise be missed by scanners that only inspect conventional `Action` statements.

---

# Policy Configuration

Security policy configuration is supported through YAML.

This separates policy configuration from the core scanning and provider architecture.

Conceptually:

```text
YAML Policy
     │
     ▼
Policy Configuration
     │
     ▼
Rule Engine
     │
     ▼
Security Findings
```

This provides a foundation for configurable security policies without requiring security rules to be rewritten for every configuration change.

Policy configuration is intended to support the longer-term development of:

* Configuration/policy packs
* Severity filtering
* Custom security requirements
* Finding suppression
* Organisation-specific security standards

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

The architecture deliberately separates:

```text
Discovery
    ↓
Normalisation
    ↓
Rule selection
    ↓
Security analysis
    ↓
Finding generation
    ↓
Reporting
```

This makes it possible to add additional providers and resource types without duplicating the security logic.

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

The provider is now integrated with the scanner's rule engine rather than operating as an isolated discovery component.

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

This approach also keeps the security rules independent from Terraform's individual resource representation.

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

The current architecture supports the same rule engine being used for:

```text
Fixtures
    │
Terraform
    │
AWS
    │
    ▼
Rule Engine
```

This is an important part of the project's provider-independent design.

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

The AWS provider therefore produces the same type of security finding as the Terraform and fixture providers.

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

JSON reporting is also part of the AWS scanning path, allowing AWS-discovered resources to produce the same structured output as Terraform and fixture scans.

---

# Testing

Testing is a major part of the project.

The latest confirmed test suite contains:

> **168 passing tests**

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
* AWS S3 discovery
* AWS-to-rule-engine integration
* JSON reporting
* CLI behaviour
* Integration paths
* YAML policy configuration

Run the complete test suite with:

```bash
pytest -q
```

Run only the AWS provider tests with:

```bash
pytest -q tests/providers/test_aws.py
```

The AWS provider tests cover areas including:

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

AWS integration tests also verify that discovered resources can pass through the normal scanning pipeline and produce security findings and JSON reporting output.

---

# Development Without AWS Credentials

The project is intentionally being developed without requiring AWS credentials to be stored in the repository.

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
* No AWS infrastructure costs during testing
* Deterministic tests
* Repeatable development
* Easier CI/CD integration

The AWS provider is designed to remain **read-only**.

The use of mocked AWS clients also allows individual AWS API behaviours and failure conditions to be tested without depending on a live account.

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

## Separation of concerns

Resource discovery, normalisation, security analysis and reporting remain separate components.

This makes the scanner easier to test, extend and maintain.

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
* [x] YAML policy configuration
* [x] JSON reporting
* [x] CLI integration
* [x] Automated test suite
* [x] Read-only AWS provider
* [x] AWS S3 bucket discovery
* [x] AWS S3 encryption discovery
* [x] AWS S3 versioning discovery
* [x] AWS S3 Block Public Access discovery
* [x] AWS S3 logging discovery
* [x] AWS S3 bucket policy discovery
* [x] Mocked AWS provider tests
* [x] AWS provider → Resource integration
* [x] AWS Resource → RuleEngine integration
* [x] AWS S3 rule integration
* [x] AWS scan → JSON reporting integration tests

## In Progress

* [ ] Expanded AWS resource discovery
* [ ] AWS IAM provider
* [ ] AWS IAM policy discovery
* [ ] AWS IAM role/trust policy discovery
* [ ] Expanded AWS security integration testing
* [ ] Live AWS environment testing
* [ ] Improved reporting
* [ ] Additional policy configuration capabilities

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

The current implementation already demonstrates the core path represented by this architecture:

```text
AWS / Terraform / Fixtures
          ↓
   Resource Model
          ↓
      Rule Engine
          ↓
       Findings
          ↓
        JSON
```

The future architecture will extend this foundation with additional AWS services, reporting formats, policy configuration and CI/CD integration.

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

The project also provides practical experience in designing a security tool around reusable interfaces rather than implementing individual checks as isolated scripts.

---

# Project Status

**Current version:** `0.1.0`

**Security rules:** 14

**Automated tests:** 168 passing

**Data sources:**

* Local fixtures
* Terraform JSON
* AWS S3 API

**AWS access:** Read-only AWS provider integrated with the Resource and RuleEngine pipeline

**AWS S3 scanning:** Implemented and covered by integration tests

**Live AWS environment testing:** Not yet completed

**Status:** Active development

---

# Repository

GitHub:

https://github.com/ledgejigsaw/AWS-Security-Scanner

Feedback, suggestions and contributions are welcome.
