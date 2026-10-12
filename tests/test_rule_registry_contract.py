from aws_security_scanner.rules.registry import get_all_rules


def test_registered_check_ids_are_unique_and_non_empty():
    rules = get_all_rules()
    check_ids = [getattr(getattr(rule, "metadata", None), "check_id", None) for rule in rules]

    assert rules, "The rule registry must not be empty"
    assert all(isinstance(check_id, str) and check_id.strip() for check_id in check_ids)
    assert len(check_ids) == len(set(check_ids)), "Duplicate security check IDs are not allowed"


def test_registered_rules_have_complete_metadata():
    required_fields = (
        "check_id",
        "service",
        "resource_type",
        "severity",
        "category",
        "title",
        "description",
        "remediation",
    )

    for rule in get_all_rules():
        metadata = getattr(rule, "metadata", None)
        assert metadata is not None, f"{rule.__name__} has no metadata"
        for field in required_fields:
            value = getattr(metadata, field, None)
            assert value is not None, f"{rule.__name__} is missing metadata field {field}"
            if isinstance(value, str):
                assert value.strip(), f"{rule.__name__} has blank metadata field {field}"
        assert getattr(rule, "resource_type", None) == metadata.resource_type, (
            f"{rule.__name__} resource type and metadata disagree"
        )
