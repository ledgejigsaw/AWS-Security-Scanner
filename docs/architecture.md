# Architecture and data flow

## Design goals

The scanner aims to keep discovery, normalisation, security logic and reporting separate. AWS API discovery is read-only, while fixture, Terraform JSON and partial Terraform HCL inputs make behaviour testable without AWS credentials.

## Processing flow

```text
Fixtures / Terraform JSON / Terraform HCL / AWS APIs
                 |
                 v
         Provider and normalisation
                 |
                 v
        Normalised Resource objects
                 |
                 v
            Rule engine
                 |
                 v
        Evidence-based Findings
                 |
                 v
          JSON / HTML / SARIF
```

## Main modules

- `providers/aws.py`: read-only AWS resource discovery and metadata collection, including ECS task definitions and services.
- `providers/fixture.py`: deterministic fixture input for offline testing.
- `providers/terraform.py` and `normalization/terraform.py`: Terraform JSON loading and conversion into the normalised resource model. Resource-reference paths preserve list indices and nested attribute paths so multiple references are not silently overwritten.\n- `providers/terraform_hcl.py`: offline, partial HCL parsing without Terraform execution, provider downloads or module expansion. Unresolved expressions are surfaced as diagnostics.
- `models/resource.py`: source-neutral resource data, including resource type, ID, attributes, source, region and optional relationships.
- `rules/`: service-specific security checks and central rule registry. ECS includes an informational review signal when a task definition explicitly reuses the same IAM role for task and execution permissions; this is not treated as proof of a vulnerability.
- `engine.py`: executes rules against compatible resources and applies policy settings.
- `policy.py`: YAML policy loading, check enablement and severity overrides.
- `reporting/`: JSON, HTML, SARIF and severity-summary output.
- `triage.py`: finding baseline/fingerprint handling and suppression behaviour.
- `cli.py`: explicit command-line interface and scan orchestration. A guided interactive mode is available via `--interactive`.\n- `multi_account.py`: sequential cross-account role assumption, expected-account validation and per-account failure reporting.\n- `graph.py`: deterministic JSON resource graph with explicit relationship provenance.

## Findings

A finding includes a stable check ID, severity, service, affected resource, title, description and remediation. Region and evidence are optional when the source provides them. Findings should state the evidence that supports the detection and avoid claiming more than the collected metadata proves.

## Security and validation boundaries

- AWS discovery is intended to be read-only.
- Secrets Manager discovery reads metadata and resource policies; it must not retrieve secret values.
- Automated tests use mocks and fixtures and do not need AWS credentials.
- Terraform HCL support is static and partial; variables/locals are not evaluated and modules are not expanded. Terraform JSON remains the preferred input when reviewed values and expanded modules are needed.
- API Gateway coverage currently targets REST APIs (v1), not HTTP APIs (v2).
- Live AWS end-to-end validation remains outstanding.
