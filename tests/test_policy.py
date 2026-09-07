import pytest

from aws_security_scanner.policy import SecurityPolicy


def test_rule_is_enabled_by_default():
    policy = SecurityPolicy()

    assert policy.is_enabled("S3-001") is True


def test_rule_can_be_disabled():
    policy = SecurityPolicy(
        {
            "S3-001": {
                "enabled": False,
            }
        }
    )

    assert policy.is_enabled("S3-001") is False


def test_unknown_rule_is_enabled_by_default():
    policy = SecurityPolicy()

    assert policy.is_enabled("UNKNOWN-001") is True


def test_rule_configuration_must_be_a_dictionary():
    with pytest.raises(TypeError):
        SecurityPolicy(
            {
                "S3-001": "invalid",
            }
        )

def test_policy_can_be_loaded_from_yaml(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules:
  S3-001:
    enabled: false

  S3-002:
    enabled: true
"""
    )

    policy = SecurityPolicy.from_yaml(policy_file)

    assert policy.is_enabled("S3-001") is False
    assert policy.is_enabled("S3-002") is True


def test_yaml_policy_with_missing_rules_uses_defaults(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules: {}
"""
    )

    policy = SecurityPolicy.from_yaml(policy_file)

    assert policy.is_enabled("S3-001") is True


def test_yaml_policy_requires_rules_mapping(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules: invalid
"""
    )

    with pytest.raises(TypeError):
        SecurityPolicy.from_yaml(policy_file)

def test_rule_enabled_must_be_boolean():
    with pytest.raises(TypeError):
        SecurityPolicy(
            {
                "S3-001": {
                    "enabled": "yes",
                }
            }
        )


def test_yaml_policy_enabled_must_be_boolean(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
rules:
  S3-001:
    enabled: yes
"""
    )

    with pytest.raises(TypeError):
        SecurityPolicy.from_yaml(policy_file)


def test_yaml_policy_root_must_be_mapping(tmp_path):
    policy_file = tmp_path / "policy.yaml"

    policy_file.write_text(
        """
- invalid
- policy
"""
    )

    with pytest.raises(TypeError):
        SecurityPolicy.from_yaml(policy_file) 