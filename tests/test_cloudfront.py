from unittest.mock import Mock

import pytest

from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.cloudfront_rules import (
    check_cloudfront_http_viewer_access,
    check_cloudfront_logging_disabled,
    check_cloudfront_missing_waf,
    check_cloudfront_weak_tls_policy,
)


def resource(**attributes):
    return Resource(
        resource_type="aws_cloudfront_distribution",
        resource_id="EDFDVBD6EXAMPLE",
        attributes=attributes,
        source="fixture",
        region=None,
    )


def test_http_viewer_access_is_flagged_when_any_behaviour_allows_http():
    findings = check_cloudfront_http_viewer_access(resource(
        viewer_protocol_policies=["redirect-to-https", "allow-all"],
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "CLOUDFRONT-001"
    assert findings[0].severity == Severity.HIGH
    assert "allow-all" in findings[0].evidence


def test_http_viewer_access_does_not_flag_https_or_unknown_values():
    assert check_cloudfront_http_viewer_access(resource(
        viewer_protocol_policies=["redirect-to-https", "https-only"],
    )) == []
    assert check_cloudfront_http_viewer_access(resource(
        viewer_protocol_policies=["unrecognised-value"],
    )) == []
    assert check_cloudfront_http_viewer_access(resource()) == []


@pytest.mark.parametrize("policy", ["SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"])
def test_legacy_tls_policy_is_flagged(policy):
    findings = check_cloudfront_weak_tls_policy(resource(
        minimum_protocol_version=policy,
    ))
    assert len(findings) == 1
    assert findings[0].check_id == "CLOUDFRONT-002"
    assert findings[0].evidence.endswith(policy)


def test_unknown_or_current_tls_policy_is_not_flagged():
    assert check_cloudfront_weak_tls_policy(resource(
        minimum_protocol_version="TLSv1.2_2021",
    )) == []
    assert check_cloudfront_weak_tls_policy(resource(
        minimum_protocol_version=None,
    )) == []


def test_explicitly_disabled_logging_is_flagged_but_unknown_is_not():
    findings = check_cloudfront_logging_disabled(resource(logging_enabled=False))
    assert len(findings) == 1
    assert findings[0].check_id == "CLOUDFRONT-003"
    assert findings[0].severity == Severity.MEDIUM
    assert check_cloudfront_logging_disabled(resource(logging_enabled=True)) == []
    assert check_cloudfront_logging_disabled(resource(logging_enabled=None)) == []
    assert check_cloudfront_logging_disabled(resource()) == []


def test_missing_waf_is_review_signal_only_when_field_was_discovered():
    findings = check_cloudfront_missing_waf(resource(web_acl_id=None))
    assert len(findings) == 1
    assert findings[0].check_id == "CLOUDFRONT-004"
    assert findings[0].severity == Severity.INFO
    assert check_cloudfront_missing_waf(resource(web_acl_id="arn:aws:wafv2:global:123:webacl/example")) == []
    assert check_cloudfront_missing_waf(resource()) == []


def test_cloudfront_provider_normalises_pagination_and_distribution_metadata(monkeypatch):
    client = Mock()
    client.list_distributions.side_effect = [
        {"DistributionList": {
            "Items": [{
                "Id": "DIST1",
                "ARN": "arn:aws:cloudfront::123:distribution/DIST1",
                "DomainName": "d111.example.cloudfront.net",
                "Enabled": True,
                "Status": "Deployed",
                "WebACLId": "",
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "allow-all"},
                "CacheBehaviors": {"Quantity": 1, "Items": [
                    {"ViewerProtocolPolicy": "https-only"}
                ]},
                "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"},
                "Logging": {"Enabled": False},
                "Origins": {"Items": [{
                    "Id": "origin1",
                    "DomainName": "example-bucket.s3.eu-west-2.amazonaws.com",
                    "OriginAccessControlId": "OAC123",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }]},
            }],
            "IsTruncated": True,
            "NextMarker": "DIST1",
        }},
        {"DistributionList": {
            "Items": [{
                "Id": "DIST2",
                "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"},
                "ViewerCertificate": {},
                "Logging": {"Enabled": True},
                "Origins": {"Items": []},
            }],
            "IsTruncated": False,
        }},
    ]
    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: Mock())
    provider = AWSProvider(cloudfront_client=client)

    resources = provider.discover_cloudfront_distributions()

    assert [item.resource_id for item in resources] == ["DIST1", "DIST2"]
    assert resources[0].region is None
    assert resources[0].attributes["viewer_protocol_policies"] == ["allow-all", "https-only"]
    assert resources[0].attributes["minimum_protocol_version"] == "TLSv1.2_2021"
    assert resources[0].attributes["logging_enabled"] is False
    assert resources[0].attributes["web_acl_id"] is None
    assert resources[0].attributes["origins"][0]["origin_access_control_id"] == "OAC123"
    assert client.list_distributions.call_args_list[1].kwargs == {"Marker": "DIST1"}


def test_cloudfront_provider_rejects_truncated_response_without_marker(monkeypatch):
    client = Mock()
    client.list_distributions.return_value = {
        "DistributionList": {"Items": [], "IsTruncated": True}
    }
    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: Mock())
    provider = AWSProvider(cloudfront_client=client)

    with pytest.raises(RuntimeError, match="without a NextMarker"):
        provider.discover_cloudfront_distributions()
