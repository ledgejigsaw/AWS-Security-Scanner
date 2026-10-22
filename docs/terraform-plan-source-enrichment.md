# Terraform plan-to-source enrichment

Use `--source-config` to link a Terraform plan JSON scan to the original HCL source tree:

```bash
terraform show -json reviewed.tfplan > reviewed-plan.json
aws-security-scan --source terraform --file reviewed-plan.json \
  --source-config ./terraform-root --format html --output reports/plan.html
```

The source directory is parsed offline using the existing HCL provider. Enrichment requires an exact canonical address match. It records `source_file`, `source_address` and `terraform_source_match=exact`; ambiguous and unmatched resources get explicit diagnostic attributes. It does not fuzzy-match module addresses, infer line/column positions, execute Terraform, initialise providers, download modules or overwrite plan values with HCL literals.

Terraform plan JSON does not contain reliable HCL line/column spans. Therefore this feature attributes files and addresses only; no source line is fabricated. Planned values, `after_unknown`, and create/update/delete actions remain authoritative. Variable overrides and provider-computed values are not re-evaluated from source.
