from aws_security_scanner.rules.registry import get_all_rules


def test_rule_registry_contains_all_rules():
    rules = get_all_rules()

    assert len(rules) == 9


def test_rule_registry_contains_iam_rules():
    rules = get_all_rules()

    rule_names = [rule.__name__ for rule in rules]

    assert "check_overly_permissive_policy" in rule_names