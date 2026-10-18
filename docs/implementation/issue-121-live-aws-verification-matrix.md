# Issue 121 — controlled live-AWS verification matrix

This checklist is a manual evidence plan, not a claim that the scanner has been validated against a live account. Standard CI remains credential-free. Use a dedicated non-production account, a named test role and an approved region list. Prepare resources out-of-band; the scanner must not create, modify or delete them.

## Pre-flight safety gates

- [ ] Verify the target account through STS before discovery.
- [ ] Use a dedicated non-production account and least-privilege read/list/describe permissions.
- [ ] Supply credentials through the AWS SDK credential chain; never place secrets in CLI arguments, URLs, fixtures or reports.
- [ ] Use synthetic resource names and store report output privately.
- [ ] Record approved regions, enabled services, scanner commit, Python and SDK versions, command, timestamp and result in a private log.
- [ ] Abort if account, role or region differs from the approved plan.

## Scenario matrix

| Domain | Positive case | Clean case | Failure or unknown case |
| --- | --- | --- | --- |
| STS | Expected account and assumed role observed | Not applicable | Wrong account aborts before discovery |
| S3 | Reviewed public-access misconfiguration detected | Private bucket with public-access blocks remains clean | AccessDenied or failed sub-call is incomplete, not clean |
| IAM | Test role and policy metadata discovered | Least-privilege fixture has no targeted risky condition | Denied policy calls produce a coverage gap |
| EC2/EBS/AMI | Pre-created test sharing exposure detected where supported | Private snapshot/image remains clean | Denied or partial API results are not treated as absence |
| KMS | Key lifecycle and grants observed where permitted | Enabled key with no risky grant remains clean | Inaccessible grant metadata remains unknown |
| CloudTrail | Trail status and selector metadata observed | Reviewed selectors represented accurately | Unknown organisation scope or denied selector reads remain unknown |
| Security Hub | Enabled hub and known finding/control result imported when opted in | Successful query with no matching findings returns zero | Disabled hub, denial or pagination failure is a coverage gap |
| GuardDuty | Enabled detector and known finding observed when opted in | Enabled detector with no matching findings returns zero | Missing/disabled detector or denied API is not clean |
| Config, Access Analyzer, Macie, Inspector | Run only where service and permissions are approved | Successful empty result distinguished from unavailable service | Disabled service and denied calls recorded as coverage gaps |
| Terraform HCL/JSON | Offline fixture produces expected findings | Secure fixture has no expected findings | Unsupported expressions/modules are unresolved, not assumed safe |

Mark a domain not exercised unless its API and expected result were observed. Not every domain has a live test harness. Mocked unit tests are not live evidence.

## Private execution record

- Scanner commit and date/time (UTC):
- Account guard passed and role/session identity:
- Regions and enabled services:
- Scenario IDs and expected/observed findings:
- Expected/observed diagnostics and incomplete domains:
- Report formats exercised:
- API errors and follow-up issues:
- Result: pass / fail / partial / not run

Do not commit account IDs, ARNs, resource names, policy documents or raw reports. A successful S3-only run does not establish that other services, regions or integrations work. A domain is live-verified only after positive, clean and applicable permission/disabled/partial-failure cases have been recorded.
