# Opt-in live AWS integration tests

The default test suite is offline and does not require AWS credentials. The
live suite is a smoke test for identity verification and read-only S3 discovery;
it does not provision or modify resources.

## Safety requirements

- Use a dedicated, non-production AWS account.
- Use a read-only role/profile limited to sts:GetCallerIdentity and
  s3:ListAllMyBuckets (plus any additional read-only permissions deliberately
  added to future live tests).
- Set the expected account ID explicitly. The test checks the STS identity
  before calling S3 and fails closed on a mismatch.
- Do not place account IDs, access keys, session tokens, ARNs, or bucket names
  in committed fixtures or test output.
- The suite must never create, modify, or delete AWS resources.

## Run

    AWS_SECURITY_SCANNER_LIVE_AWS=1 \
    AWS_SECURITY_SCANNER_EXPECTED_ACCOUNT_ID=123456789012 \
    pytest -m live_aws -q

Optionally select a configured profile with
AWS_SECURITY_SCANNER_AWS_PROFILE=security-test. The example account ID above
is a placeholder, not a real account.

Without the opt-in variable, the test is skipped. When opted in, a missing or
malformed expected account ID is a test failure rather than an implicit
fallback. Live tests must be reported separately from mocked unit tests.
