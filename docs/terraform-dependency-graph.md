# Terraform dependency graph and static reference resolution

The HCL provider builds a deterministic graph after discovering the selected root module and permitted local modules. It resolves only exact references to scalar attributes explicitly present in the normalized resource model. Provider-computed attributes, absent keys, expression-bearing values and unknown references remain unresolved.

Export the graph while scanning HCL:

```bash
aws-security-scan --source hcl --file ./terraform-root \
  --terraform-graph-output reports/terraform-graph.json \
  --format html --output reports/terraform.html
```

The graph JSON contains canonical resource addresses, source files, relationship edges, unresolved edges and cycle membership. The provider also retains a `static_reference_resolution` summary for resolved and unresolved attribute references.

This is not a full Terraform evaluator. It does not evaluate arbitrary functions, dynamic blocks, data sources or provider-computed values, and does not execute Terraform, initialise providers, fetch modules or require AWS credentials. The HCL parser does not currently provide reliable source spans. Module outputs are not treated as resolved unless represented by a supported explicit static value.
