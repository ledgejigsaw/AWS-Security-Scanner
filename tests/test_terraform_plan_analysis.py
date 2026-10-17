from aws_security_scanner.models.resource import Resource
from aws_security_scanner.terraform_plan_analysis import analyze_terraform_plan


def resource(name, **attributes):
    return Resource(resource_type="aws_s3_bucket", resource_id=name, attributes=attributes, source="terraform", region="eu-west-2")


def test_destroy_and_replacement_are_distinguished():
    diagnostics = analyze_terraform_plan([
        resource("removed", terraform_address="module.data.aws_s3_bucket.old", terraform_plan_actions=["delete"], terraform_removed=True),
        resource("replace", terraform_address="module.data.aws_s3_bucket.current", terraform_plan_actions=["delete", "create"]),
    ])
    assert {item["diagnostic_id"] for item in diagnostics} == {"TF-PLAN-DESTROY", "TF-PLAN-REPLACEMENT"}
    assert next(item for item in diagnostics if item["resource_address"].endswith("old"))["severity"] == "MEDIUM"
    assert next(item for item in diagnostics if item["resource_address"].endswith("current"))["severity"] == "HIGH"


def test_unknown_security_values_are_review_not_compliant_or_insecure():
    diagnostics = analyze_terraform_plan([resource(
        "bucket", terraform_plan_actions=["update"],
        terraform_unknown_attributes=["server_side_encryption_configuration", "tags.Environment", "acl"],
    )])
    assert len(diagnostics) == 1
    assert diagnostics[0]["diagnostic_id"] == "TF-PLAN-UNKNOWN-SECURITY-VALUE"
    assert diagnostics[0]["severity"] == "REVIEW"
    assert "cannot be confirmed" in diagnostics[0]["message"]


def test_create_update_and_noop_without_unknown_security_values_are_quiet():
    diagnostics = analyze_terraform_plan([
        resource("created", terraform_plan_actions=["create"]),
        resource("updated", terraform_plan_actions=["update"], terraform_unknown_attributes=["tags.Name"]),
        resource("stable", terraform_plan_actions=["no-op"]),
    ])
    assert diagnostics == []


def test_nested_module_address_and_diagnostics_are_deterministic():
    item = resource("bucket", terraform_address="module.parent.module.child.aws_s3_bucket.data", terraform_plan_actions=["delete"], terraform_unknown_attributes=["bucket_policy"])
    first = analyze_terraform_plan([item])
    second = analyze_terraform_plan([item])
    assert first == second
    assert all(diagnostic["resource_address"].startswith("module.parent.module.child.") for diagnostic in first)
