# Issue #186 — All enabled AWS regions

## Implemented in this PR

- Added a pure region-classification helper for EC2 DescribeRegions responses,
  including opt-in-required regions that are not enabled.
- Added a failure-isolated multi-region orchestration API. Regional successes
  are retained if a different region fails.
- Added a single global-discovery callback, invoked at most once, plus
  deterministic region results and safe error categories.
- Added offline tests for enabled/disabled region classification, regional
  partial failures, global deduplication, and error-message redaction.

## API and integration boundary

The helpers live in aws_security_scanner.multi_region. Existing CLI scans
continue to use their established explicit-region behaviour. The helper does
not silently switch existing users to all-region scans. A subsequent CLI
integration can expose an explicit opt-in flag and map the provider's regional
and global discovery functions into the callback contract.

## Validation

Tests have been added but have not been executed in this editing session.
GitHub Actions and the local full pytest suite remain the merge gate.

## Permissions and operational notes

Region enumeration requires ec2:DescribeRegions. Discovery permissions vary
by service and should be granted read-only. Multi-region scans can increase
API calls and throttling risk; the report marks regional failures incomplete
rather than treating failed discovery as an empty or clean result.
