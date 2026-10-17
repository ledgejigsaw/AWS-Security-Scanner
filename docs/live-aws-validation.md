# Controlled live AWS validation

## Safety model

The live suite is deliberately opt-in and is not part of ordinary CI. It is read-only: it does not create, modify, or delete AWS resources. Use a dedicated non-production account and a pre-created S3 bucket whose configuration and expected findings have been reviewed. Do not use a production account or put account IDs, bucket names, credentials, policy documents, or other sensitive output into committed fixtures.

The test verifies the active account through STS. If the identity differs from the configured expected account, the test fails before discovery starts.

## Configure and run

Create a dedicated account and a test bucket out-of-band. Configure an AWS CLI profile with only the read permissions required for the S3 discovery operations and STS identity check. The scanner does not need access keys passed as arguments.

```bash
export AWS_PROFILE=security-scanner-test
export AWS_SECURITY_SCANNER_LIVE_TESTS=1
export AWS_SECURITY_SCANNER_LIVE_EXPECTED_ACCOUNT_ID=123456789012
export AWS_SECURITY_SCANNER_LIVE_EXPECTED_BUCKET=scanner-fixture-bucket
export AWS_SECURITY_SCANNER_LIVE_REGION=eu-west-2

# Use NONE for an intentionally clean fixture, or a comma-separated exact
# list of check IDs expected for this bucket, for example S3-001,S3-007.
export AWS_SECURITY_SCANNER_LIVE_EXPECTED_CHECK_IDS=NONE

pytest -m live_aws -q
```

Replace the example account and bucket values with your own dedicated test resources. AWS_SECURITY_SCANNER_LIVE_EXPECTED_CHECK_IDS is required: NONE means no scanner findings are expected for that bucket; otherwise provide the exact expected check-ID set. Review the fixture's intended state and expected checks before each validation run.

If AWS_SECURITY_SCANNER_LIVE_TESTS is not exactly 1, the test skips. Setting it to 1 without all required guard variables fails rather than silently skipping. Standard CI should not set this variable and must continue to run without AWS credentials.

## Scope and limits

The initial live test exercises only S3 discovery and rule evaluation in one selected region, plus STS identity verification. It is not evidence that every service, region, API permission, or optional integration works. Record the tested account guard, region, fixture configuration, expected check IDs, timestamp, scanner commit, and result in a private validation log. Never attach credentials or raw sensitive resource data.

The external fixture owner is responsible for provisioning and cleaning up the bucket. The test itself performs no cleanup because it performs no writes.
