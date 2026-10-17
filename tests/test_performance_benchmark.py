from copy import deepcopy

import pytest

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.performance import replicate_resources


def test_replicate_resources_assigns_unique_ids_and_copies_attributes():
    template = Resource(
        resource_type="aws_s3_bucket",
        resource_id="example",
        attributes={"encryption": {"enabled": False}},
        source="terraform",
        region="eu-west-2",
        relationships={"logging.target": "aws_s3_bucket.logs"},
        account_id="111111111111",
    )

    resources = replicate_resources([template], 3)

    assert [resource.resource_id for resource in resources] == [
        "example-benchmark-000000",
        "example-benchmark-000001",
        "example-benchmark-000002",
    ]
    assert all(resource.account_id == "111111111111" for resource in resources)
    resources[0].attributes["encryption"]["enabled"] = True
    assert resources[1].attributes == {"encryption": {"enabled": False}}
    assert template.attributes == {"encryption": {"enabled": False}}


def test_replicate_resources_rejects_invalid_count_and_missing_templates():
    with pytest.raises(ValueError, match="non-negative integer"):
        replicate_resources([], -1)
    with pytest.raises(ValueError, match="at least one template"):
        replicate_resources([], 1)
    with pytest.raises(ValueError, match="non-negative integer"):
        replicate_resources([], True)
