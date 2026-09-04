# AWS Security Scanner

A Python-based AWS cloud security posture assessment tool designed to identify common AWS security misconfigurations.

The project is being developed as a security engineering portfolio project, with an emphasis on:

- Security-by-design
- Least privilege
- Modular architecture
- Automated testing
- Infrastructure security
- Reusable security rules
- Separation of security logic from configuration sources
- Extensible provider architecture

The long-term objective is to provide a read-only security assessment capability for AWS environments, Terraform infrastructure-as-code, and controlled test fixtures.

---

## Project Status

**Current version: 0.1.0**

The project is currently being developed using local security fixtures. This allows the security detection engine to be developed and tested without requiring an active AWS account or live cloud infrastructure.

The architecture is being designed so that the same security rules can eventually analyse configuration obtained from multiple sources.

### Completed

- Python package structure
- Modular security-rule architecture
- Security finding data model
- Normalised resource data model
- Fixture-based testing architecture
- Separation between configuration sources and security rules
- S3 public-access detection
- Automated tests for S3 public-access detection

### Current Test Status

```text
2 passed
