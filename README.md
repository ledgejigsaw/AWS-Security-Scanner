# Project Status

Current version: 0.1.0

The project is currently being developed primarily using local security fixtures and Terraform JSON configuration, with structured JSON reporting and a command-line interface implemented.

The security-analysis architecture is now established around a normalised resource model, allowing the same security rules to operate independently of the configuration source.

The current implementation supports:

* Normalised security resource model
* Fixture-based configuration discovery
* Terraform JSON resource discovery
* Terraform resource relationship resolution
* Terraform S3 resource aggregation
* Modular security rules
* Resource-aware rule execution
* Centralised rule registration
* Security rule metadata
* Standardised security findings
* JSON reporting
* Command-line scanning
* Automated unit and integration testing
* S3 security controls
* IAM security controls

The scanner currently operates without requiring an active AWS account or live AWS infrastructure. AWS API discovery is intentionally planned for a later development phase.

### Current test status

**103 tests passing**

The S3 security rules and Terraform S3 normalisation layer currently have **100% statement coverage**.

This includes tests for:

* S3 security-rule behaviour
* Known-good configurations
* Known-bad configurations
* Terraform resource discovery
* Terraform resource relationships
* Terraform S3 normalisation
* Terraform S3 configuration aggregation
* Missing Terraform relationships
* Orphaned Terraform S3 configuration resources
* Engine integration
* Rule registration
* JSON reporting
* CLI behaviour
* IAM security controls
* Security policy configuration

---

# Testing

The project uses `pytest` for automated security-rule, normalisation, provider, reporting and architecture testing.

Run the complete test suite with:

```bash
pytest -v
```

Current result:

```text
103 passed
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
* Terraform S3 versioning aggregation
* Terraform S3 encryption aggregation
* Terraform S3 Block Public Access aggregation
* Terraform S3 logging aggregation
* Terraform S3 bucket-policy aggregation
* JSON reporting
* CLI behaviour
* Security policy configuration

The tests are deliberately designed to run without live AWS infrastructure.

### S3 and Terraform coverage

The S3 rule implementation and Terraform S3 normalisation layer have been tested to **100% statement coverage**.

Coverage was verified using:

```bash
pytest --cov=aws_security_scanner.rules.s3_rules \
       --cov=aws_security_scanner.normalization.terraform \
       --cov-report=term-missing \
       tests/rules/test_s3_rules.py \
       tests/normalization/test_terraform_normalization.py \
       tests/providers/test_terraform.py
```

Result:

```text
Name                                             Stmts   Miss   Cover
--------------------------------------------------------------------
src/aws_security_scanner/normalization/terraform.py   38      0   100%
src/aws_security_scanner/rules/s3_rules.py             52      0   100%
--------------------------------------------------------------------
TOTAL                                                  90      0   100%

37 passed
```

The tests also explicitly cover defensive Terraform normalisation behaviour, including configuration resources with no bucket relationship and configuration resources referencing buckets that do not exist.

---

# S3 Security Controls

The scanner currently implements six S3 security controls.

## S3-001 — Publicly Accessible Bucket

**Severity:** `CRITICAL`

Detects an S3 bucket configured for public access.

The rule generates an evidence-based security finding containing:

* Check ID
* Severity
* Service
* Resource
* Title
* Description
* Remediation
* Region
* Evidence

Public object storage can represent a significant data-exposure risk, particularly where buckets contain sensitive, confidential or regulated information.

## S3-002 — Server-Side Encryption Disabled

**Severity:** `HIGH`

Detects S3 buckets where server-side encryption is disabled.

The rule operates against the normalised S3 resource model, allowing encryption configuration to be evaluated consistently regardless of whether the resource originated from a fixture or Terraform configuration.

## S3-003 — Bucket Versioning Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where versioning is disabled.

Terraform S3 versioning configuration is aggregated into the logical S3 bucket resource during normalisation.

## S3-004 — Block Public Access Disabled

**Severity:** `HIGH`

Detects S3 buckets where the Block Public Access configuration is disabled.

Terraform `aws_s3_bucket_public_access_block` resources are associated with their logical S3 bucket during normalisation.

The normalised resource records the Block Public Access configuration so that the security rule can evaluate the resulting security posture.

## S3-005 — Server Access Logging Disabled

**Severity:** `MEDIUM`

Detects S3 buckets where server access logging is disabled.

Terraform `aws_s3_bucket_logging` resources are associated with their logical S3 bucket during normalisation.

The normalisation layer uses the canonical `logging` security attribute while retaining the detailed logging configuration where required.

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

The rule also evaluates wildcard principals represented through AWS or federated principal structures.

The rule recommends restricting access to the specific AWS accounts, roles or services that require access.

Both single-statement and multi-statement bucket policies are supported.

---

# Terraform S3 Normalisation

Terraform can represent a single logical S3 bucket using multiple Terraform resources.

The scanner therefore performs relationship resolution followed by S3 resource aggregation.

For example:

```text
aws_s3_bucket
        +
aws_s3_bucket_versioning
        +
aws_s3_bucket_server_side_encryption_configuration
        +
aws_s3_bucket_public_access_block
        +
aws_s3_bucket_logging
        +
aws_s3_bucket_policy
        |
        v
Normalised S3 Resource
```

The Terraform provider identifies relationships between these resources.

The normalisation layer then associates related configuration with the corresponding logical S3 bucket.

Supported Terraform S3 configuration currently includes:

* Bucket versioning
* Server-side encryption
* Block Public Access
* Server access logging
* Bucket policies

This allows the security rules to analyse the logical AWS security configuration rather than requiring each rule to understand Terraform's resource decomposition.

Terraform normalisation also safely handles incomplete configuration. Configuration resources without a bucket relationship, or resources referencing a bucket that does not exist, are ignored rather than incorrectly associated with another resource.

---

# Development Roadmap

## Phase 1 — Core Architecture

* [x] Normalised resource model
* [x] Resource-aware rule engine
* [x] Rule metadata
* [x] Central rule registry
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

### Terraform S3

* [x] Terraform S3 resource discovery
* [x] Terraform S3 relationship resolution
* [x] Terraform S3 versioning aggregation
* [x] Terraform S3 encryption aggregation
* [x] Terraform S3 Block Public Access aggregation
* [x] Terraform S3 logging aggregation
* [x] Terraform S3 bucket-policy aggregation

**Phase 2 status: Complete**

Phase 2 has been implemented and verified through unit, integration and normalisation testing.

The complete project test suite currently contains **103 passing tests**.

## Phase 3 — IAM Security

* [x] IAM resource fixtures
* [x] IAM-001 — Unrestricted IAM permissions
* [x] IAM-002 — Wildcard IAM permissions
* [x] IAM-003 — Excessive administrative permissions
* [x] IAM-004 — Insecure IAM role trust policy
* [ ] Terraform IAM normalisation
* [ ] Additional IAM controls

## Phase 4 — Terraform Security

* [x] Terraform JSON resource discovery
* [x] Terraform resource normalisation
* [x] Terraform resource relationship resolution
* [x] Terraform S3 resource aggregation
* [ ] Direct Terraform/HCL parsing
* [ ] Terraform-specific security fixtures
* [ ] Additional Terraform resource normalisation
* [ ] Terraform CI/CD integration

## Future Development

Planned future areas include:

* Live AWS configuration discovery
* AWS authentication and read-only access
* Additional AWS service coverage
* EC2 security controls
* VPC and network security controls
* Additional Terraform normalisation
* Direct Terraform/HCL parsing
* CI/CD security gates
* HTML reporting
* Expanded risk scoring
* Security policy configuration
* Architecture visualisation
