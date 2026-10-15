# Project documentation

This documentation is version-controlled with the scanner and should be updated when architecture, rule behaviour, supported inputs, or development workflows change.

## Pages

- [Architecture and data flow](architecture.md)
- [Service and rule coverage matrix](rule-coverage.md)
- [Developing a security rule](rule-development.md)
- [Security rule specification template](rule-template.md)
- [Contributor guide](../CONTRIBUTING.md)
- [Testing and validation](testing-and-validation.md)
- [Baseline history and suppression governance](baseline-history.md)
- [WAF and application-edge posture](waf-application-edge.md)
- [AWS-native security-service posture](security-services.md)
- [CloudTrail and KMS coverage expansion](cloudtrail-kms-coverage.md)
- [EBS snapshot protection](ebs-snapshot-protection.md)
- [Container build and runtime usage](../README.md#container-usage)

## Project status

The scanner is under active development. It supports fixture-based scans, Terraform JSON and partial HCL normalisation and read-only AWS discovery for the services listed in the main [README](../README.md), including CloudFront, AWS Config and native Security Hub/GuardDuty finding ingestion. Automated tests use mocks and fixtures; a live AWS account end-to-end scan has not yet been completed.

## Keeping these pages current

When a feature is added or changed, update the relevant page in the same pull request as the code. Keep claims about supported services and checks aligned with the rule registry, provider implementation and tests. Do not describe a service as live-validated unless a real-account validation has actually been performed.

- [Multi-account assessment foundation](multi-account-assessment.md)
