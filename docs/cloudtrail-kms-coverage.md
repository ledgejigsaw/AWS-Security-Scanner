# CloudTrail and KMS coverage expansion

## CloudTrail checks

- **CT-004 — CloudWatch Logs integration absent (INFO):** emitted only when the provider has the `cloudwatch_logs_log_group_arn` attribute and its value is empty. This is a review signal for near-real-time monitoring; it does not prove CloudTrail events are not delivered to S3.
- **CT-005 — Recent delivery error (MEDIUM):** emitted when trail status contains a non-empty `LatestDeliveryError`. Evidence is bounded to 240 characters.

The provider uses `cloudtrail:DescribeTrails` and `cloudtrail:GetTrailStatus` for the current inventory/status path. The new checks use returned metadata; they do not alter trails or destinations. A successful `IsLogging` state does not by itself prove destination delivery is healthy.

## KMS checks

- **KMS-004 — Broad unconditional cross-account access (MEDIUM):** identifies an Allow statement with no Condition where an AWS principal account differs from the account encoded in the key ARN and the action set includes `kms:*`, wildcard actions, or selected sensitive cryptographic/administrative actions.

This is a review signal. Cross-account key use can be intentional, and this check is not a full policy simulator. It does not evaluate every IAM policy, service control policy, grants, resource relationship or all condition operators. Policies with conditions are not flagged by this check; that does not prove the conditions are correct or sufficient. Malformed or unavailable policy documents are not treated as clean evidence.

## Required permissions and limitations

Existing discovery uses read-only CloudTrail trail description/status and KMS key-list, key-description, rotation-status and key-policy APIs. Relevant IAM actions include `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` and `kms:GetKeyPolicy`.

- No configuration is changed.
- Missing optional CloudWatch Logs integration is informational, not a universal failure.
- Delivery errors are signals for investigation and may reflect temporary or destination-specific conditions.
- Cross-account KMS findings require owner review and must not be treated as proof of malicious access.
- Tests use synthetic policy and API responses. No live AWS account validation is claimed.
