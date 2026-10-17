# Upstream scanner capability gap analysis

## Purpose and method

This project is aiming for broader and deeper results comparable in quality to established tools, not a superficial rule-count match. The comparison must separate live cloud posture checks from Infrastructure-as-Code (IaC) analysis because they operate on different evidence and have different completeness limits.

The companion file [upstream-tool-gap-analysis.json](upstream-tool-gap-analysis.json) is a versioned gap ledger. It deliberately marks check-by-check mappings as not reviewed until an individual check has been compared semantically. The deterministic inventory exporter is the source of truth for locally registered rule metadata:

    python scripts/export_rule_inventory.py --output reports/rule-inventory.json

The exported inventory should be regenerated in CI or review whenever the registry changes. Do not use a stale hard-coded rule count as the basis for upstream parity claims.

## Reference projects

- [Prowler](https://github.com/prowler-cloud/prowler): AWS-focused CSPM checks, native findings and compliance-oriented output. Compare live AWS checks, scope, permissions, severity, evidence and false-positive behaviour.
- [Checkov](https://github.com/bridgecrewio/checkov): IaC policy scanning, Terraform variable handling and module-aware analysis. Compare HCL/plan coverage, module resolution and unsupported-expression reporting.
- [Trivy](https://github.com/aquasecurity/trivy): IaC misconfiguration and wider security scanning. Compare IaC checks and developer/CI workflow integration.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite): multi-service cloud posture inventory and findings. Compare discovery breadth and handling of partial visibility.
- [Cloudsplaining](https://github.com/salesforce/cloudsplaining): IAM policy risk analysis. Compare privilege-risk semantics and policy condition handling.
- [Parliament](https://github.com/duo-labs/parliament): IAM policy linting. Compare malformed/overly permissive policy detection and explainability.

These tools have different purposes and dependency/licensing models. The goal is to reuse publicly documented ideas and test cases where permitted, not to copy code blindly or claim direct parity.

## Priority order

1. **Make Terraform evidence trustworthy first.** Resolve root input files and supported locals; then build explicit module/resource dependency resolution. Unsupported values remain unknown.
2. **Make incompleteness visible.** Reports and exit codes must clearly show when a module, expression or data source was not assessed.
3. **Create a reproducible benchmark corpus.** Include positive, negative and unknown examples with expected finding IDs and diagnostics. Pin upstream references and record versions.
4. **Deepen high-impact AWS domains.** Prioritise IAM policy semantics, network exposure/reachability, encryption and public data access, audit logging, backup/recovery, container and serverless controls.
5. **Add attack-path reasoning only after relationship correctness is measured.** A path needs explicit edges, provenance, assumptions and unresolved-edge reporting; resource proximity alone is not a path.
6. **Measure parity rather than claim it.** For every mapped upstream check, record equivalent/partial/not-equivalent/not-applicable/not-reviewed, rationale, source URL, review date, and test evidence.

## Rule mapping acceptance standard

A mapping should be reviewed against:
- Exact resource and service scope.
- Detection condition and exclusions.
- Severity rationale and whether the upstream check is informational or a confirmed failure.
- Evidence collected and permissions required.
- Behaviour when data is absent, access is denied, or values are unknown.
- Remediation safety and any data-loss implications.
- Framework mappings, if any, without claiming that a finding establishes compliance.
- Upstream license and attribution obligations before adapting implementation or fixtures.

A similarly named rule is not necessarily equivalent. Preserve local stable check IDs and add upstream references to rule documentation or metadata only after a semantic review.
