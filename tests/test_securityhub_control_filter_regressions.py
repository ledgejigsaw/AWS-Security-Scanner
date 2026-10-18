from unittest.mock import Mock

from aws_security_scanner.providers.aws import AWSProvider


def test_securityhub_applies_workflow_and_compliance_filters():
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    provider.securityhub_client.get_findings.return_value = {"Findings": []}

    assert provider.get_securityhub_findings(
        workflow_statuses=["NEW", "NOTIFIED"],
        compliance_status="FAILED",
        record_state="ACTIVE",
    ) == []

    assert provider.securityhub_client.get_findings.call_args.kwargs["Filters"] == {
        "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        "WorkflowStatus": [
            {"Comparison": "EQUALS", "Value": "NEW"},
            {"Comparison": "EQUALS", "Value": "NOTIFIED"},
        ],
        "ComplianceStatus": [{"Comparison": "EQUALS", "Value": "FAILED"}],
    }


def test_securityhub_deduplication_preserves_distinct_product_identity():
    provider = AWSProvider.__new__(AWSProvider)
    provider.securityhub_client = Mock()
    first = {"Id": "same-id", "ProductArn": "arn:product/a"}
    duplicate = {"Id": "same-id", "ProductArn": "arn:product/a"}
    other_product = {"Id": "same-id", "ProductArn": "arn:product/b"}
    provider.securityhub_client.get_findings.return_value = {
        "Findings": [first, duplicate, other_product]
    }

    assert provider.get_securityhub_findings(limit=10) == [first, other_product]
