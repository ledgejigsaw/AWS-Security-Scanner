from aws_security_scanner.rules.decorators import rule_for


def test_rule_for_assigns_resource_type():
    @rule_for("aws_s3_bucket")
    def test_rule(resource):
        return []

    assert test_rule.resource_type == "aws_s3_bucket"


def test_rule_for_preserves_rule_callable():
    @rule_for("aws_s3_bucket")
    def test_rule(resource):
        return []

    assert callable(test_rule)