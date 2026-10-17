# Terraform plan risk diagnostics

`aws_security_scanner.terraform_plan_analysis.analyze_terraform_plan(resources)` examines metadata attached by the Terraform plan provider and emits deterministic diagnostics for resource deletion/replacement and security-relevant values unknown at plan time.

Use a plan JSON document produced by `terraform show -json <planfile>` and the scanner's existing Terraform JSON source support. Destructive-change diagnostics are review prompts, not a prediction of downtime or data loss. Unknown security-relevant values are reported with severity `REVIEW`; they are not converted to `False`, and should not be interpreted as proof of an insecure configuration.

This module does not run Terraform, evaluate arbitrary HCL expressions, fetch remote modules, or prove that a planned change will succeed. The diagnostics are a reusable analysis API and do not replace existing configuration rules.