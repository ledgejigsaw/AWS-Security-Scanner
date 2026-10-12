# CI/CD and scheduled scanning

The example workflow at `.github/workflows/security-scan-example.yml` runs a credential-free Terraform JSON scan for relevant pull requests and can be started manually. It uploads SARIF as a 14-day artifact. Fixture scans exercise the scanner against synthetic data; they do **not** assess an AWS account.

## Manual live AWS scan (opt-in)

The workflow's `workflow_dispatch` input supports `scan_mode=aws`. Configure GitHub Actions OIDC in AWS first, and supply the role ARN and region. The role trust policy must constrain the repository and workflow identity. Grant only the read actions required by the discovery methods you intend to run; do not use administrator access or long-lived access keys. The example requests short-lived credentials with OIDC and does not store AWS keys in repository secrets.

Before enabling this in a production repository:
- Review the scanner's current AWS API call set and required IAM actions.
- Use a non-production account and a dedicated read-only role first.
- Confirm the trust policy's audience and subject conditions match your repository and branch/environment.
- Treat permission errors, throttling, and incomplete discovery as an incomplete assessment, not evidence that a control is safe.
- Restrict report visibility and retention. Reports can reveal resource names and security posture; review them before sharing or uploading them.
- Do not commit scan reports or sensitive Terraform plans/state. The workflow uploads SARIF as an artifact with a 14-day retention period.

## SARIF and code-scanning upload

The workflow retains a SARIF artifact but does not automatically publish it to GitHub Code Scanning. Repositories that have Code Scanning enabled can add `github/codeql-action/upload-sarif` after reviewing repository policy and permissions, with job-level `security-events: write`. Keep this permission scoped to the upload job and consider how pull-request forks and untrusted workflow changes are handled.

## Exit codes and blocking gates

The current CLI returns a successful process status after writing a report even when findings are present. Runtime/configuration errors generally fail the command, but not every provider currently emits a machine-readable completeness status. Therefore this example is **report-only**: it does not use findings as a merge-blocking gate. Do not interpret a successful workflow as proof of a clean account. A blocking gate should wait for explicit exit-code semantics that distinguish policy findings, scan errors, and incomplete discovery.

## Scheduling

To schedule a real-account scan, add a cron trigger only after the OIDC trust, read-only permissions, report access, and operational owner have been reviewed. Prefer a weekly cadence initially and run against a non-production account. Scheduled fixture scans only test scanner execution; they are not a substitute for live-account assessment.
