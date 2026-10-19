# Controlled live AWS validation plan

## Purpose and evidence boundary

This is a manual, opt-in verification procedure for a dedicated non-production AWS account. It supplements, but does not replace, fixture and mocked API tests. Mock tests prove expected handling of supplied responses; only a recorded real-account run provides evidence about the account, region, permissions and API behaviour actually exercised. Never claim full live validation from a successful unit-test run.

## Safety requirements

- Use a dedicated non-production account and a separate least-privilege read-only role/profile.
- Do not use production credentials, commit account exports, or attach raw inventories to public issues.
- Confirm the AWS account ID and principal ARN with STS before every run. Stop if the account is unexpected.
- Do not grant write, remediation, resource-creation or deletion permissions. Provision any test fixtures out of band.
- Use short-lived credentials or an AWS CLI profile; never place secrets in command-line arguments, URLs, source control, logs or reports.
- Record scanner commit, date/time, selected regions/services, expected fixture state, permission profile, coverage statuses and outcome in a private validation log.

## Repeatable procedure

1. Create or select a disposable test account and a dedicated read-only role.
2. Configure only the AWS APIs needed for the service domains under test, including STS `GetCallerIdentity`.
3. Provision a small set of known resources out of band. Record their expected posture without storing sensitive configuration in the repository.
4. Run the scanner first against a deliberately narrow service and region scope. Confirm the displayed account identity before allowing discovery to proceed.
5. Verify one known-positive configuration and one known-negative configuration where safe test fixtures exist.
6. Repeat with an intentionally disabled service and with one deliberately denied read permission. The scanner must report the disabled/denied condition as a coverage gap, not as proof that no findings exist.
7. Exercise pagination with enough safe test resources or native findings to cross a page boundary where feasible; confirm that bounds and truncation are visible.
8. Repeat for each selected region and each service domain. Record skipped domains explicitly.
9. Review reports for secrets, account identifiers and infrastructure details before sharing. Keep raw reports private and redact before attaching any excerpt.
10. Remove test resources using the account owner's normal change process; the scanner itself performs no writes or cleanup.

## Service-domain evidence matrix

Complete one row per service/domain actually selected. Do not mark a row validated merely because the CLI ran successfully.

| Domain / API family | Positive evidence | Negative / empty evidence | Disabled or denied evidence | Region / pagination evidence |
|---|---|---|---|---|
| Identity and caller validation (STS) | Expected account/principal accepted | N/A | Mismatched account rejected before discovery | Region-independent preflight recorded |
| S3 | Known test bucket is discovered and expected controls evaluated | A deliberately compliant test bucket produces no unexpected finding | Denied S3 read is reported as failed/partial coverage | Selected region and list pagination outcome recorded |
| IAM and account-level identity controls | Known test role/policy metadata is discovered | No unexpected findings for the baseline fixture | Denied IAM reads do not appear as clean coverage | Global/regional handling recorded as implemented |
| Network and compute domains (for example EC2/VPC) | Known test resource appears with expected identity | Empty scope is distinguishable from failed discovery | Denied API calls are visible in coverage | Every selected region recorded |
| Storage, database and backup domains | Known supported resources are discovered | Empty inventory distinguished from unsupported scope | Disabled service or denied access is a gap | Page bounds and selected regions recorded |
| Native security services (Security Hub, GuardDuty, Access Analyzer, Inspector, Macie) | Known native finding is imported where available | Empty successful query distinguished from unavailable service | Disabled service / denied action is a gap | Native finding pagination, filters and regional coverage recorded |
| Other supported domains | Name the exact discovery operation(s) exercised | Record expected empty behaviour | Record disabled/denied behaviour | Record region and continuation-token behaviour |

The matrix is intentionally evidence-driven: populate it only for APIs that the current scanner version actually calls. If a service is not enabled or cannot safely be seeded, mark it not exercised rather than passed.

## Permission design

Start from the repository's current discovery implementation and documented permission inventory. Grant only the read/list/describe actions needed for the selected scope, plus STS identity verification. Do not use `ReadOnlyAccess` as a substitute for reviewing the actual action set: managed policies can be broader than required and can change over time. Keep optional native integrations disabled unless their individual permissions are intentionally granted.

## Interpreting results

- `success`: the discovery operations completed; it is not proof that unsupported APIs or resources were covered.
- `empty`: the selected discovery completed and returned no resources.
- `partial` or `failed`: treat the assessment as incomplete; do not interpret missing findings as resolved risk.
- A clean report is only meaningful within the explicitly selected services, regions, permissions and supported resource types.
- This process is read-only. It does not enable services, change configuration, remediate findings or create test resources.

## Existing opt-in live test

The repository's S3 live test is separately gated by environment variables and validates a single expected account, region and bucket. Follow its instructions in this document's existing test module / repository documentation; ordinary CI must not require credentials. The test is a narrow smoke test, not a substitute for completing the service-domain matrix above.
