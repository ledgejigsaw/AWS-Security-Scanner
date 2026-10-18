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

## Prioritised implementation roadmap

The live backlog is tracked as GitHub issues. The order below deliberately puts evidence quality ahead of rule-count expansion:

1. **Documentation and validation:** [#234](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/234) generated inventory/coverage checks, this gap ledger (#176), and controlled live-account verification [#121](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/121).
2. **Detection accuracy:** [#227](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/227) IAM policy semantics, [#228](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/228) evidence-backed network reachability, and [#229](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/229) all-enabled-region discovery.
3. **IaC context:** [#172](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/172) cross-file dependency graph, [#174](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/174) opt-in external modules, and [#232](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/232) plan-to-source enrichment.
4. **High-value AWS coverage:** [#230](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/230) analytics/database/search services and [#231](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/231) backup/recovery posture; continue native finding work in [#113](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/113) and [#114](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/114).
5. **Measured parity:** [#233](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/233) differential benchmarks against reviewed Prowler and Checkov samples.
6. **Later expansion:** provider-neutral architecture [#58](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/58), Azure [#59](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/59), GCP [#60](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/60), and attack-path analysis only after graph relationships are validated.

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
