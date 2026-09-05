from aws_security_scanner.rules.registry import get_all_rules


def test_rule_registry_contains_s3_rules():
    rules = get_all_rules()

    assert len(rules) == 6


def test_rule_registry_contains_callable_rules():
    rules = get_all_rules()

    assert all(callable(rule) for rule in rules)