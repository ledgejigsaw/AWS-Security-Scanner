# Terraform HCL static-analysis scope

The HCL provider is deliberately non-evaluating: it parses local HCL with `python-hcl2`, does not execute Terraform, and does not download providers or modules. `--file` accepts either one `.tf` file or a module-root directory. Directory mode parses only the direct `*.tf` children together; nested directories are treated as separate module/example boundaries.

## Supported and explicitly limited constructs

- Literal resource blocks are normalised into the canonical resource model.
- Nested blocks are normalised where supported by the rule model.
- `count`, `for_each`, dynamic blocks and unresolved variable/local/module expressions produce informational diagnostics rather than being treated as known-safe values.
- Module blocks are not expanded; a diagnostic placeholder identifies the module address.
- Data-source blocks are not queried or evaluated; `IAC-HCL-003` identifies the data-source address separately from unresolved expressions.
- Source file and logical resource address are carried into JSON, HTML and SARIF findings. Exact line/column spans are not emitted because the current parser integration does not expose reliable source spans.

`IAC-HCL-001` is reserved for expressions the scanner identifies as unresolved; `IAC-HCL-002` means a module call was not expanded; `IAC-HCL-003` means a data source was not evaluated. These are coverage limitations, not proof of a vulnerability or proof that the configuration is secure. A diagnostic is not a vulnerability finding. It means the static scan could not establish the final resource value or full configuration scope. Review the rendered evidence and use a reviewed `terraform show -json` plan when the plan's values are available.

## Example

```bash
aws-security-scan --source hcl --file main.tf --format sarif --output reports/iac.sarif

# Scan all .tf files directly in one module root
aws-security-scan --source hcl --file ./terraform/network --format html --output reports/network.html
```

Malformed HCL fails with a contextual input error. The scanner does not silently skip parse errors or substitute an empty configuration.
