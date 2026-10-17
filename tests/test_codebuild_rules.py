from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.codebuild_rules import (
    check_codebuild_plaintext_sensitive_environment_variables,
    check_codebuild_privileged_mode,
)


def project(**attributes):
    defaults = {
        "privileged_mode": False,
        "environment_variables": [],
    }
    defaults.update(attributes)
    return Resource(
        resource_type="aws_codebuild_project",
        resource_id="demo",
        attributes=defaults,
        source="aws",
        region="eu-west-2",
    )


def test_codebuild_privileged_mode_is_detected_only_when_explicitly_enabled():
    assert check_codebuild_privileged_mode(project(privileged_mode=True))[0].check_id == "CB-001"
    assert check_codebuild_privileged_mode(project(privileged_mode=False)) == []
    assert check_codebuild_privileged_mode(project(privileged_mode=None)) == []


def test_codebuild_sensitive_plaintext_detection_reports_names_not_values():
    finding = check_codebuild_plaintext_sensitive_environment_variables(project(
        environment_variables=[
            {"name": "API_TOKEN", "type": "PLAINTEXT"},
            {"name": "DB_PASSWORD", "type": "SECRETS_MANAGER"},
            {"name": "NORMAL_SETTING", "type": "PLAINTEXT"},
        ]
    ))[0]
    assert finding.check_id == "CB-002"
    assert finding.evidence == "plaintext_sensitive_variable_names=API_TOKEN"
    assert "DB_PASSWORD" not in finding.evidence
    assert check_codebuild_plaintext_sensitive_environment_variables(project(
        environment_variables=[{"name": "API_TOKEN", "type": "SECRETS_MANAGER"}]
    )) == []
