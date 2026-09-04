# AWS Security Scanner

A Python-based AWS cloud security posture assessment tool designed to identify common AWS security misconfigurations.

The project is being developed as a security engineering portfolio project, with an emphasis on:

* Security-by-design
* Least privilege
* Modular architecture
* Automated testing
* Infrastructure security
* Reusable security rules
* Separation of security logic from cloud-provider APIs

## Project Status

**Current version: 0.1.0**

The project is currently being developed using local security fixtures. This allows the security detection engine to be developed and tested without requiring an active AWS account.

### Completed

* Python package structure
* Modular security-rule architecture
* Security finding data model
* Fixture-based testing architecture
* S3 public-access detection
* Automated tests for S3 public-access detection

### Current Security Check

| Check ID | Service | Security Check             | Severity |
| -------- | ------- | -------------------------- | -------- |
| S3-001   | S3      | Publicly accessible bucket | CRITICAL |

## Architecture

The scanner is designed around separation of concerns:

```text
                 Security Scanner
                        |
              +---------+---------+
              |                   |
          Providers             Rules
              |                   |
       +------+-------+           |
       |              |           |
    Fixtures         AWS       Analysis
       |              |           |
       +------+-------+           |
              |                   |
              +---------> Findings
                              |
                         Reporting
```

The security rules are deliberately separated from the AWS provider.

This means the security logic can be tested against controlled fixtures before connecting to a live AWS environment.

## Project Structure

```text
AWS-Security-Scanner/
│
├── policies/
│
├── reports/
│
├── src/
│   └── aws_security_scanner/
│       ├── models/
│       │   └── finding.py
│       │
│       ├── providers/
│       │   ├── aws.py
│       │   └── fixture.py
│       │
│       ├── reporting/
│       │
│       └── rules/
│           └── s3_rules.py
│
├── tests/
│   ├── fixtures/
│   │   ├── iam/
│   │   └── s3/
│   │       ├── insecure_bucket.json
│   │       └── secure_bucket.json
│   │
│   └── rules/
│       └── test_s3_rules.py
│
├── .gitignore
├── pyproject.toml
└── README.md
```

## Installation

Clone the repository and create a Python virtual environment:

```bash
git clone https://github.com/ledgejigsaw/AWS-Security-Scanner.git
cd AWS-Security-Scanner

python3 -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Install development dependencies:

```bash
pip install -e ".[dev]"
```

## Testing

The project uses `pytest` for automated testing.

Run:

```bash
pytest
```

The current test suite validates both the insecure and secure S3 fixture scenarios.

Expected result:

```text
2 passed
```

## Current S3 Detection

The first security rule detects publicly accessible S3 buckets.

An insecure fixture:

```json
{
    "bucket_name": "company-sensitive-data",
    "region": "eu-west-2",
    "public": true,
    "encryption": false,
    "versioning": false,
    "logging": false
}
```

should generate:

```text
S3-001
Severity: CRITICAL
Issue: S3 bucket is publicly accessible
```

A secure fixture should generate no finding for this rule.

## Security Design

The project intentionally uses a rule-based architecture.

Security checks are implemented independently from the mechanism used to obtain cloud configuration data.

This provides several advantages:

1. Security rules can be unit tested without AWS credentials.
2. Security logic can be validated using known-good and known-bad configurations.
3. AWS API integration can be added independently.
4. Additional cloud providers or configuration sources could potentially be supported later.
5. Security findings have a consistent data model.

The long-term objective is to provide evidence for each finding, including the affected resource, severity, description and recommended remediation.

## Roadmap

### S3 Security

* [x] S3-001 — Public bucket detection
* [ ] S3-002 — Encryption disabled
* [ ] S3-003 — Versioning disabled
* [ ] S3-004 — S3 Block Public Access configuration
* [ ] S3-005 — Server access logging

### IAM Security

* [ ] Overly permissive IAM policies
* [ ] Wildcard permissions
* [ ] Excessive administrative permissions
* [ ] Insecure trust policies
* [ ] Cross-account access
* [ ] IAM privilege-escalation paths
* [ ] MFA assessment
* [ ] Access-key assessment

### Compute Security

* [ ] EC2 public exposure
* [ ] IMDSv2 enforcement
* [ ] Public security groups
* [ ] Unencrypted EBS volumes
* [ ] Public AMIs and snapshots

### Network Security

* [ ] VPC configuration
* [ ] Internet gateways
* [ ] Route tables
* [ ] Security groups
* [ ] Network ACLs
* [ ] Public subnets

### AWS Integration

* [ ] AWS/Boto3 provider
* [ ] AWS CLI/profile support
* [ ] Multi-region scanning
* [ ] Read-only scanner role
* [ ] Multi-account support

### Reporting

* [ ] Rich terminal reporting
* [ ] JSON output
* [ ] HTML reports
* [ ] Severity filtering
* [ ] Risk scoring
* [ ] CIS benchmark mapping
* [ ] NIST mapping

### Advanced Features

* [ ] Terraform integration
* [ ] Infrastructure architecture visualisation
* [ ] CI/CD security scanning
* [ ] Historical findings
* [ ] Security posture dashboard

## Disclaimer

This project is intended for authorised security assessment, education and defensive security engineering.

Do not use the scanner against AWS environments without appropriate authorisation.

## Licence

Licence to be determined.

