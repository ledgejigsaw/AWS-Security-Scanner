# Project documentation

This documentation is version-controlled with the scanner and should be updated when architecture, rule behaviour, supported inputs, or development workflows change.

## Pages

- [Architecture and data flow](architecture.md)
- [Developing a security rule](rule-development.md)
- [Testing and validation](testing-and-validation.md)

## Project status

The scanner is under active development. It supports fixture-based scans, Terraform JSON normalisation and read-only AWS discovery for the services listed in the main [README](../README.md). Automated tests use mocks and fixtures; a live AWS account end-to-end scan has not yet been completed.

## Keeping these pages current

When a feature is added or changed, update the relevant page in the same pull request as the code. Keep claims about supported services and checks aligned with the rule registry, provider implementation and tests. Do not describe a service as live-validated unless a real-account validation has actually been performed.
