# Contributing to AWS Security Scanner

Thank you for considering a contribution. This project is a read-only AWS cloud security posture assessment tool. Contributions should improve detection quality without weakening least-privilege, data-minimisation, testability or reporting guarantees.

## Development setup

Requirements: Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest -q
```

The automated suite uses synthetic fixtures and mocked AWS APIs. No AWS account or credentials should be required for the standard test suite.

## Workflow

1. Check existing issues and pull requests before starting work.
2. Open or update an issue describing the security problem, scope, assumptions and acceptance criteria.
3. Create a focused branch from `main`.
4. Add tests for the insecure state, expected safe state and incomplete/unknown state.
5. Implement the smallest coherent change.
6. Update the README and relevant documentation in the same change.
7. Run the full test suite and inspect the diff for accidental secrets, generated files and unrelated changes.
8. Open a pull request with a clear summary, security rationale, test evidence, limitations and any required permissions.
9. Do not merge until required CI checks have completed successfully.

## Architecture conventions

- Keep AWS API discovery in `providers/aws.py`; keep security decisions in `rules/`.
- Convert source data into the normalised `Resource` model before evaluating rules.
- Use the central registry in `rules/registry.py`; a rule not registered there will not run.
- Use the shared `Finding` model and `Finding.from_rule` where appropriate.
- Keep fixture, Terraform JSON and AWS-source behaviour consistent when they represent the same resource.
- Do not introduce write/remediation calls into discovery.

## Security rule requirements

Every rule must have:
- A stable, unique check ID (for example, `S3-001`).
- A supported normalised resource type.
- Service, category, severity, title, description and actionable remediation metadata.
- Evidence sufficient to explain why the rule fired.
- A severity rationale based on impact, exposure and confidence.
- Positive, negative and incomplete-metadata tests.
- Documentation of assumptions, false-positive risks and policy-overridable baselines.

Prefer explicit evidence. Unknown values, missing permissions, unsupported APIs and incomplete discovery must not silently become “secure” or “insecure”. Public exposure and optional controls should be described as review signals when context is insufficient to establish a vulnerability.

## AWS API and sensitive-data rules

- Use read-only AWS APIs only.
- Never retrieve Secrets Manager secret values or SSM SecureString contents.
- Never log, fixture, commit or report credentials, secret values, tokens or production-sensitive exports.
- Do not retrieve object bodies, database rows, queue messages, SNS payloads, container image layers or application data unless a separately approved issue explicitly establishes a safe need.
- Paginate APIs that expose continuation tokens and test pagination.
- Treat access-denied, throttling, malformed responses and unavailable metadata explicitly; do not convert failures into clean scans.
- Document the minimum IAM permissions needed for each discovery path.
- Do not claim live AWS validation unless it has actually been performed.

## Pull request checklist

- [ ] Scope and security rationale are explained.
- [ ] Tests cover insecure, safe and unknown/incomplete states.
- [ ] Provider mocks cover pagination/error paths where relevant.
- [ ] New checks are registered and IDs are unique.
- [ ] README rule counts and service coverage are updated.
- [ ] Architecture/rule/testing docs are updated where needed.
- [ ] No secret values, credentials, generated reports or unrelated artifacts are included.
- [ ] `pytest -q` passes locally and CI is green.
- [ ] Live-account validation status is stated accurately.

See [rule development](docs/rule-development.md), [the rule template](docs/rule-template.md), [architecture](docs/architecture.md) and [testing and validation](docs/testing-and-validation.md).
