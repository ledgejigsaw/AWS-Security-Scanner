# Compliance mapping examples

The scanner supports versioned, user-supplied mappings that annotate findings in JSON, HTML and SARIF. A starter mapping is provided at `examples/compliance/cis-aws-foundations-benchmark-1.4.0.json`.

Run it with a fixture, Terraform or AWS scan:

```bash
aws-security-scan --source fixture --file tests/fixtures --compliance-mapping examples/compliance/cis-aws-foundations-benchmark-1.4.0.json --format json --output reports/compliance.json
```

The example is based on the control identifiers and descriptions published in the [AWS Security Hub CIS AWS Foundations Benchmark reference](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html). It is deliberately partial and illustrative, not a complete CIS assessment or a certification claim. The mappings use confidence labels and rationales to make the relationship between a scanner check and a control explicit.

A finding mapped to a control is not equivalent to a control passing or failing. A finding only reports what the scanner observed for a particular resource; unmapped checks and undiscovered resources are not silently considered compliant. Review the framework's official assessment procedure and confirm that scan discovery coverage is sufficient before using output as audit evidence.

When updating mappings:
- preserve the framework name and exact version;
- use official source material for control IDs and titles;
- choose `direct`, `partial` or `contextual` confidence honestly;
- explain limitations in the rationale;
- run the mapping validator against the current registry;
- do not infer that a framework's entire control population has been assessed from a subset of mapped findings.
