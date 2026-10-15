from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.ec2_rules import check_imdsv1_enabled


def _instance(metadata_options):
    return Resource(
        resource_type="aws_instance",
        resource_id="example-instance",
        attributes={"metadata_options": metadata_options},
        source="terraform",
        region="eu-west-2",
    )


def test_imdsv1_rule_handles_hcl_nested_block_list_and_detects_optional_tokens():
    findings = check_imdsv1_enabled(
        _instance([{"http_tokens": "optional"}])
    )

    assert len(findings) == 1
    assert findings[0].check_id == "EC2-007"
    assert findings[0].evidence == "HttpTokens=optional"


def test_imdsv1_rule_handles_empty_hcl_nested_block_list():
    assert check_imdsv1_enabled(_instance([])) == []


def test_imdsv1_rule_handles_dictionary_metadata_options():
    assert check_imdsv1_enabled(
        _instance({"http_tokens": "required"})
    ) == []


def test_imdsv1_rule_handles_missing_or_unexpected_metadata_options():
    assert check_imdsv1_enabled(_instance(None)) == []
    assert check_imdsv1_enabled(_instance("unknown")) == []
