from aws_security_scanner.rules.registry import get_all_rules


def test_rule_registry_contains_all_rules():
    rules = get_all_rules()

    assert len(rules) == 61


def test_rule_registry_contains_iam_rules():
    rules = get_all_rules()
    rule_names = [rule.__name__ for rule in rules]

    assert "check_overly_permissive_policy" in rule_names
    assert "check_wildcard_permissions" in rule_names
    assert "check_excessive_administrative_permissions" in rule_names
    assert "check_insecure_trust_policy" in rule_names
    assert "check_privilege_escalation_permissions" in rule_names
    assert "check_sensitive_iam_action" in rule_names
    assert "check_broad_trust_relationship" in rule_names


def test_rule_registry_contains_s3_tls_rule():
    rules = get_all_rules()
    rule_names = [rule.__name__ for rule in rules]

    assert "check_tls_enforcement" in rule_names


def test_rule_registry_contains_cloudtrail_and_kms_rules():
    rule_names = [rule.__name__ for rule in get_all_rules()]

    assert "check_cloudtrail_logging" in rule_names
    assert "check_cloudtrail_multi_region" in rule_names
    assert "check_kms_key_rotation" in rule_names
    assert "check_kms_key_pending_deletion" in rule_names



def test_rule_registry_contains_cloudtrail_validation_and_kms_policy_rules():
    rule_names = [rule.__name__ for rule in get_all_rules()]

    assert "check_cloudtrail_log_file_validation" in rule_names
    assert "check_kms_key_policy_wildcard_access" in rule_names

def test_rule_registry_contains_rds_rules():
    rule_names = [rule.__name__ for rule in get_all_rules()]

    assert "check_rds_storage_encryption" in rule_names
    assert "check_rds_public_accessibility" in rule_names
    assert "check_rds_backup_retention" in rule_names
    assert "check_rds_deletion_protection" in rule_names

def test_rule_registry_contains_lambda_rules():
    rule_names = [rule.__name__ for rule in get_all_rules()]

    assert "check_lambda_public_function_url" in rule_names
    assert "check_lambda_wildcard_invoke_policy" in rule_names

def test_rule_registry_contains_secrets_manager_rules():
    rule_names = [rule.__name__ for rule in get_all_rules()]

    assert "check_secret_rotation_disabled" in rule_names
    assert "check_secret_wildcard_resource_policy" in rule_names
