import json

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.providers.terraform import TerraformProvider


def test_terraform_plan_preserves_unknown_values_and_change_actions(tmp_path):
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [{
                    "address": "aws_s3_bucket.example",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "example",
                    "values": {"bucket": "example-bucket", "region": "eu-west-2"},
                }],
                "child_modules": [{
                    "resources": [{
                        "address": "module.storage.aws_s3_bucket.nested",
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "nested",
                        "values": {"bucket": "nested-bucket"},
                    }],
                }],
            }
        },
        "resource_changes": [{
            "address": "aws_s3_bucket.example",
            "type": "aws_s3_bucket",
            "name": "example",
            "change": {
                "actions": ["update"],
                "before": {"bucket": "example-bucket"},
                "after": {"bucket": "example-bucket"},
                "after_unknown": {"server_side_encryption_configuration": {"rule": True}},
            },
        }],
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")

    resources = TerraformProvider(path).discover()
    by_address = {resource.attributes["terraform_address"]: resource for resource in resources}

    assert set(by_address) == {
        "aws_s3_bucket.example",
        "module.storage.aws_s3_bucket.nested",
    }
    example = by_address["aws_s3_bucket.example"]
    assert example.attributes["terraform_plan_actions"] == ["update"]
    assert example.attributes["terraform_unknown_attributes"] == [
        "server_side_encryption_configuration.rule"
    ]
    assert by_address["module.storage.aws_s3_bucket.nested"].resource_id == "nested"


def test_terraform_plan_keeps_delete_diagnostic_but_engine_skips_posture_rules(tmp_path):
    plan = {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": []}},
        "resource_changes": [{
            "address": "aws_s3_bucket.retired",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "retired",
            "change": {
                "actions": ["delete"],
                "before": {"bucket": "retired-bucket"},
                "after": None,
                "after_unknown": {},
            },
        }],
    }
    path = tmp_path / "delete-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    resources = TerraformProvider(path).discover()

    assert len(resources) == 1
    assert resources[0].attributes["terraform_removed"] is True
    assert resources[0].attributes["terraform_plan_actions"] == ["delete"]

    def rule(resource):
        return [Finding(
            check_id="TEST-001",
            severity=Severity.HIGH,
            service="Test",
            resource=resource.resource_id,
            title="Should not run",
            description="Test",
            remediation="Test",
        )]

    rule.resource_type = "aws_s3_bucket"
    assert RuleEngine([rule]).scan(resources) == []


def test_legacy_terraform_json_shape_remains_supported(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({
        "resource": {"aws_s3_bucket": {"legacy": {"bucket": "legacy-bucket"}}}
    }), encoding="utf-8")

    resources = TerraformProvider(path).discover()
    assert len(resources) == 1
    assert resources[0].resource_id == "legacy"
    assert resources[0].attributes["bucket"] == "legacy-bucket"
    assert "terraform_address" not in resources[0].attributes
