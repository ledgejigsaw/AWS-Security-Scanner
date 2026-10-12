from aws_security_scanner.rules.registry import get_all_rules


def test_cloudfront_checks_are_registered():
    check_ids = {rule.metadata.check_id for rule in get_all_rules()}
    assert {
        "CLOUDFRONT-001",
        "CLOUDFRONT-002",
        "CLOUDFRONT-003",
        "CLOUDFRONT-004",
    } <= check_ids
