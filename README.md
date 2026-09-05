# AWS Security Scanner

A Python-based **AWS Cloud Security Posture Management (CSPM)** tool designed to identify common AWS security misconfigurations.

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

The long-term objective is to provide a **read-only security assessment capability** for AWS environments, Terraform infrastructure-as-code, and controlled test fixtures.

---

## Project Status

**Current version: 0.1.0**

The project is currently being developed using local security fixtures. This allows the security detection engine to be developed and tested without requiring an active AWS account or live cloud infrastructure.

The architecture is designed so that the same security rules can eventually analyse configuration obtained from multiple sources.

### Completed

* Python package structure
* Modular security-rule architecture
* Security finding data model
* Normalised resource data model
* Fixture-based testing architecture
* Separation between configuration sources and security rules
* Fixture provider
* S3 public-access detection
* S3 encryption detection
* S3 versioning detection
* S3 Block Public Access detection
* S3 server access logging detection
* Automated tests for known-good and known-bad S3 configurations

### Current Test Status

```text
8 passed
```

---

# Current Security Checks

| Check ID | Service | Security Check                  | Severity | Status      |
| -------- | ------- | ------------------------------- | -------- | ----------- |
| S3-001   | S3      | Publicly accessible bucket      | CRITICAL | Implemented |
| S3-002   | S3      | Server-side encryption disabled | HIGH     | Implemented |
| S3-003   | S3      | Bucket versioning disabled      | MEDIUM   | Implemented |
| S3-004   | S3      | Block Public Access disabled    | HIGH     | Implemented |
| S3-005   | S3      | Server access logging disabled  | MEDIUM   | Implemented |

Additional security controls will be added incrementally as the security engine develops.

---

# Architecture

The scanner is built around a separation-of-concerns architecture.

Configuration is obtained from a data source, converted into a normalised `Resource` representation, evaluated by independent security rules, and converted into standardised security findings.

```text
                         DATA SOURCES
                              |
              +---------------+---------------+
              |               |               |
          Fixtures        Terraform          AWS
              |               |               |
              +---------------+---------------+
                              |
                              v
                    +-------------------+
                    |     Resource      |
                    |      Model        |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |   Security Rules  |
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

Security rules should not depend directly on AWS SDK responses, Terraform syntax, or fixture-specific structures.

Instead, providers are responsible for converting source-specific configuration into the common `Resource` model.

---

# Normalised Resource Model

A common `Resource` model sits between configuration providers and security rules.

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
  Security Rule
        |
        v
     Finding
```

The security rules should not need to know whether configuration originated from:

* A local JSON fixture
* Terraform/HCL
* The AWS API

This allows the security detection engine to be developed and tested independently from cloud-provider APIs.

For example:

```text
Local Fixture ─────┐
                   |
Terraform ─────────┼──> Resource ──> S3 Rules
                   |
AWS API ───────────┘
```

This reduces coupling between data acquisition and security analysis while allowing the same security controls to operate across multiple configuration sources.

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
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py
│       │   └── resource.py
│       │
│       ├── providers/
│       │   ├── __init__.py
│       │   ├── aws.py
│       │   └── fixture.py
│       │
│       ├── reporting/
│       │   └── __init__.py
│       │
│       └── rules/
│           ├── __init__.py
│           └── s3_rules.py
│
├── tests/
│   ├── fixtures/
│   │   └── s3/
│   │       ├── insecure_bucket.json
│   │       └── secure_bucket.json
│   │
│   └── rules/
│       ├── __init__.py
│       └── test_s3_rules.py
│
├── .gitignore
├── pyproject.toml
└── README.md
```

Some provider and reporting components are currently placeholders for functionality planned for later development.

---

# Installation

## Requirements

* Python 3.11+
* Git
* `pip`
* Python virtual environment

The current fixture-based implementation does **not** require an AWS account or AWS credentials.

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

The project uses `pytest` for automated security-rule testing.

Run the test suite with:

```bash
pytest
```

Current result:

```text
8 passed
```

The test suite validates both known-bad and known-good S3 configurations.

The current tests verify that:

1. A publicly accessible S3 bucket generates an `S3-001` `CRITICAL` finding.
2. A private S3 bucket does not generate an `S3-001` finding.
3. An unencrypted S3 bucket generates an `S3-002` `HIGH` finding.
4. An encrypted S3 bucket does not generate an `S3-002` finding.
5. A bucket with versioning disabled generates an `S3-003` `MEDIUM` finding.
6. A bucket with versioning enabled does not generate an `S3-003` finding.
7. A bucket with S3 Block Public Access disabled generates an `S3-004` `HIGH` finding.
8. A bucket with server access logging disabled generates an `S3-005` `MEDIUM` finding.
9. A bucket with server access logging enabled does not generate an `S3-005` finding.

> Note: The project is being developed incrementally, so the exact number of tests will increase as additional security controls are implemented.

---

# Current S3 Security Checks

## S3-001 — Publicly Accessible Bucket

**Severity:** `CRITICAL`

Detects an S3 bucket configured for public access.

Example:

```json
{
    "bucket_name": "company-sensitive-data",
    "region": "eu-west-2",
    "public": true,
    "encryption": false,
    "versioning": false,
    "logging": false,
    "block_public_access": false
}
```

The scanner generates a finding containing:

```text
Check ID: S3-001
Severity: CRITICAL
Service: S3
Resource: company-sensitive-data
Issue: S3 bucket is publicly accessible
```

The finding also contains:

* Description
* Remediation guidance
* AWS region
* Evidence supporting the finding

Publicly accessible object storage can represent a significant data-exposure risk, particularly where buckets contain sensitive, confidential, or regulated information.

---

## S3-002 — Server-Side Encryption Disabled

**Severity:** `HIGH`

Detects S3 buckets where server-side encryption is disabled.

Example:

```json
"encryption": false
```

The scanner generates a finding containing:

```text
Check ID: S3-002
Severity: HIGH
Service: S3
Resource: company-sensitive-data
Issue: S3 bucket encryption is disabled
```

The rule currently recommends enabling server-side encryption using either SSE-S3 or SSE-KMS according to the organisation's security requirements.

---

## S3-003 — Bucket Versioning Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where versioning is disabled.

Example:

```json
"versioning": false
```

The scanner generates a finding containing:

```text
Check ID: S3-003
Severity: MEDIUM
Service: S3
Resource: company-sensitive-data
Issue: S3 bucket versioning is disabled
```

Versioning can provide additional protection against accidental deletion or overwriting of objects and improve data recovery capabilities.

---

## S3-004 — Block Public Access Disabled

**Severity:** `HIGH`

Detects S3 buckets where Block Public Access is disabled.

Example:

```json
"block_public_access": false
```

The scanner generates a finding containing:

```text
Check ID: S3-004
Severity: HIGH
Service: S3
Resource: company-sensitive-data
Issue: S3 Block Public Access is disabled
```

The finding identifies the configuration value responsible for the detection and recommends enabling S3 Block Public Access.

The current fixture implementation represents Block Public Access using a simplified boolean value.

The future AWS provider will model the underlying S3 Block Public Access configuration more accurately, including the individual AWS controls.

---

## S3-005 — Server Access Logging Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where server access logging is disabled.

Example:

```json
"logging": false
```

The scanner generates a finding containing:

```text
Check ID: S3-005
Severity: MEDIUM
Service: S3
Resource: company-sensitive-data
Issue: S3 bucket access logging is disabled
```

Without access logging, requests made against the bucket may not be recorded, reducing visibility into access activity and making security investigations more difficult.

The remediation recommends enabling S3 server access logging and configuring an appropriate destination for the access logs.

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

This provides a standard interface for security checks and future reporting functionality.

The findings model is designed so that results can eventually be consumed by:

* Terminal reporting
* JSON reports
* HTML reports
* CI/CD pipelines
* Security dashboards
* Risk-scoring systems

---

# Security Design

The project intentionally uses a modular, rule-based architecture.

Security checks are implemented independently from the mechanism used to obtain cloud configuration data.

## Testability

Security rules can be unit tested without requiring AWS credentials or live infrastructure.

Known-good and known-bad configurations are represented as controlled fixtures.

This provides deterministic test conditions and reduces the risk of introducing regressions into existing security controls.

## Separation of Concerns

The provider is responsible for obtaining and normalising configuration.

The security rule is responsible for determining whether that configuration violates a security requirement.

Reporting is responsible for presenting the resulting findings.

This prevents cloud-provider API logic from becoming tightly coupled to security-analysis logic.

## Reusability

Security rules are designed to operate against the common `Resource` model regardless of whether the underlying configuration originated from:

```text
Fixture
Terraform
AWS API
```

## Controlled Development

Security checks can be developed and validated locally before introducing live AWS API integration.

This reduces the need to develop and test security functionality directly against live infrastructure.

## Extensibility

Additional security rules and configuration providers can be introduced without redesigning the entire scanner.

---

# Security Philosophy

The project is being developed around the following principles.

### Read-Only by Design

The scanner is intended to assess cloud configuration rather than modify infrastructure.

The long-term AWS implementation will use read-only permissions wherever practical.

### Least Privilege

The eventual AWS integration should use the minimum permissions required to perform security assessment activities.

### Evidence-Based Findings

Security findings should identify the configuration that caused the finding rather than simply reporting that a check failed.

### Deterministic Security Rules

Where possible, rules should produce deterministic results from a given configuration.

### Automated Testing

Security logic should be covered by automated tests using known-good and known-bad configurations.

### Separation of Security Logic

Security rules should remain independent from AWS API implementation details.

---

# Infrastructure as Code

Terraform is planned as a first-class configuration source for the scanner.

The intended architecture is:

```text
Terraform HCL
     |
     v
Terraform Provider
     |
     v
Resource Model
     |
     v
Security Rules
     |
     v
Findings
```

This will allow security issues to be identified before infrastructure is deployed.

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

This creates the potential for the scanner to operate as a security gate within infrastructure-as-code workflows.

---

# Roadmap

## Phase 1 — Foundation

* [x] Python package structure
* [x] Finding data model
* [x] Normalised resource model
* [x] Fixture-based testing
* [x] Fixture provider
* [x] Modular security rules
* [x] Automated tests

---

## Phase 2 — S3 Security

* [x] S3-001 — Public bucket detection
* [x] S3-002 — Encryption disabled
* [x] S3-003 — Versioning disabled
* [x] S3-004 — S3 Block Public Access configuration
* [x] S3-005 — Server access logging
* [ ] Additional S3 security checks
* [ ] S3 bucket policy analysis
* [ ] S3 ACL analysis
* [ ] S3 public-access policy evaluation
* [ ] S3 lifecycle configuration analysis
* [ ] S3 object-lock assessment

---

## Phase 3 — Infrastructure as Code

* [ ] Terraform/HCL parsing
* [ ] Terraform resource discovery
* [ ] Terraform → Resource normalisation
* [ ] Terraform security scanning
* [ ] Terraform security fixtures
* [ ] Terraform-specific automated tests
* [ ] Detection of security misconfigurations before deployment

---

## Phase 4 — IAM Security

* [ ] Overly permissive IAM policies
* [ ] Wildcard permissions
* [ ] Excessive administrative permissions
* [ ] Insecure trust policies
* [ ] Cross-account access
* [ ] IAM privilege-escalation paths
* [ ] MFA assessment
* [ ] Access-key assessment

---

## Phase 5 — Compute Security

* [ ] EC2 public exposure
* [ ] IMDSv2 enforcement
* [ ] Public security groups
* [ ] Unencrypted EBS volumes
* [ ] Public AMIs
* [ ] Public snapshots

---

## Phase 6 — Network Security

* [ ] VPC configuration
* [ ] Internet gateways
* [ ] Route tables
* [ ] Security groups
* [ ] Network ACLs
* [ ] Public subnets
* [ ] Unnecessary internet exposure
* [ ] Network segmentation checks

---

## Phase 7 — AWS Integration

* [ ] AWS/Boto3 provider
* [ ] AWS CLI/profile support
* [ ] Multi-region scanning
* [ ] Read-only scanner role
* [ ] Multi-account support
* [ ] AWS authentication validation
* [ ] AWS API error handling
* [ ] Rate-limit handling

---

## Phase 8 — Reporting

* [ ] Rich terminal reporting
* [ ] JSON output
* [ ] HTML reports
* [ ] Severity filtering
* [ ] Risk scoring
* [ ] Evidence presentation
* [ ] CIS benchmark mapping
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

This approach allows each security control to be independently developed, tested and validated before moving to the next layer.

The development process follows the general:

```text
RED → GREEN → REFACTOR
```

cycle:

1. Write a test representing the required security behaviour.
2. Confirm the test fails for the expected reason.
3. Implement the minimum functionality required.
4. Confirm the test passes.
5. Refactor where appropriate without changing behaviour.
6. Commit the completed security control.

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

---

# Disclaimer

This project is intended for authorised security assessment, education and defensive security engineering.

Do not use the scanner against AWS environments without appropriate authorisation.

The project is provided for educational and security-engineering purposes and should not be considered a replacement for a comprehensive commercial cloud security platform or professional security assessment.

---

# Licence

Licence to be determined.
