from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.cloudtrail_rules import (
    check_cloudtrail_cloudwatch_logs_integration,
    check_cloudtrail_delivery_error,
)
from aws_security_scanner.rules.kms_rules import check_kms_cross_account_access


def resource(resource_type, resource_id, **attributes):
    return Resource(
        resource_type=resource_type,
        resource_id=resource_id,
        attributes=attributes,
        source="fixture",
        region="eu-west-2",
    )


def test_cloudtrail_logs_integration_is_review_signal_and_unknown_is_not_flagged():
    trail = resource("aws_cloudtrail_trail", "trail-1", cloudwatch_logs_log_group_arn=None)
    findings = check_cloudtrail_cloudwatch_logs_integration(trail)
    assert findings[0].check_id == "CT-004"
    assert check_cloudtrail_cloudwatch_logs_integration(
        resource("aws_cloudtrail_trail", "trail-1", cloudwatch_logs_log_group_arn="arn:aws:logs:eu-west-2:123:log-group:trail")
    ) == []
    assert check_cloudtrail_cloudwatch_logs_integration(resource("aws_cloudtrail_trail", "trail-1")) == []


def test_cloudtrail_delivery_error_requires_explicit_nonempty_error():
    findings = check_cloudtrail_delivery_error(
        resource("aws_cloudtrail_trail", "trail-1", latest_delivery_error="Access denied")
    )
    assert findings[0].check_id == "CT-005"
    assert check_cloudtrail_delivery_error(resource("aws_cloudtrail_trail", "trail-1", latest_delivery_error="")) == []
    assert check_cloudtrail_delivery_error(resource("aws_cloudtrail_trail", "trail-1")) == []


def test_kms_cross_account_policy_flags_only_unconditional_allow_of_sensitive_actions():
    key_arn = "arn:aws:kms:eu-west-2:111122223333:key/example"
    external = "arn:aws:iam::444455556666:role/consumer"
    risky = resource("aws_kms_key", key_arn, arn=key_arn, key_policy={
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": external},
                       "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*"}]
    })
    findings = check_kms_cross_account_access(risky)
    assert findings[0].check_id == "KMS-004"
    assert "444455556666" in findings[0].evidence


def test_kms_cross_account_check_ignores_conditions_deny_and_unknown_policy():
    key_arn = "arn:aws:kms:eu-west-2:111122223333:key/example"
    external = "arn:aws:iam::444455556666:role/consumer"
    conditioned = resource("aws_kms_key", key_arn, arn=key_arn, key_policy={
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": external},
                       "Action": "kms:*", "Resource": "*", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]
    })
    denied = resource("aws_kms_key", key_arn, arn=key_arn, key_policy={
        "Statement": [{"Effect": "Deny", "Principal": {"AWS": external}, "Action": "kms:*", "Resource": "*"}]
    })
    assert check_kms_cross_account_access(conditioned) == []
    assert check_kms_cross_account_access(denied) == []
    assert check_kms_cross_account_access(resource("aws_kms_key", key_arn, key_policy=None)) == []


def test_cloudtrail_provider_normalises_destination_metadata(monkeypatch):
    class CloudTrail:
        def describe_trails(self, **kwargs):
            return {"trailList": [{
                "Name": "org-trail",
                "TrailARN": "arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail",
                "HomeRegion": "eu-west-2",
                "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-west-2:111122223333:log-group:trail",
                "CloudWatchLogsRoleArn": "arn:aws:iam::111122223333:role/CloudTrailLogs",
            }]}

        def get_trail_status(self, **kwargs):
            return {"IsLogging": True, "LatestDeliveryError": ""}

    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: object())
    provider = AWSProvider(cloudtrail_client=CloudTrail(), region="eu-west-2")
    trails = provider.discover_cloudtrail_trails()
    assert trails[0].attributes["cloudwatch_logs_log_group_arn"].endswith(":trail")
    assert trails[0].attributes["cloudwatch_logs_role_arn"].endswith("CloudTrailLogs")
