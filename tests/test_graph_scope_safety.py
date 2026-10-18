"""Regression tests for resource-graph scope safety."""
from aws_security_scanner.graph import build_resource_graph
from aws_security_scanner.models.resource import Resource


def test_typed_relationship_does_not_cross_account_when_resource_ids_collide():
    source = Resource(
        resource_type="aws_subnet", resource_id="subnet-a",
        attributes={"vpc_id": "vpc-shared"}, source="aws",
        region="eu-west-2", account_id="111111111111",
    )
    foreign_target = Resource(
        resource_type="aws_vpc", resource_id="vpc-shared",
        attributes={}, source="aws", region="eu-west-2",
        account_id="222222222222",
    )

    graph = build_resource_graph([source, foreign_target])

    assert graph["edges"] == []
    assert any(
        item["relationship"] == "vpc_id" and item["status"] == "unknown"
        for item in graph["unresolved_relationships"]
    )


def test_typed_relationship_does_not_cross_region_when_scope_differs():
    source = Resource(
        resource_type="aws_subnet", resource_id="subnet-a",
        attributes={"vpc_id": "vpc-shared"}, source="aws",
        region="eu-west-2", account_id="111111111111",
    )
    foreign_target = Resource(
        resource_type="aws_vpc", resource_id="vpc-shared",
        attributes={}, source="aws", region="us-east-1",
        account_id="111111111111",
    )

    graph = build_resource_graph([source, foreign_target])

    assert graph["edges"] == []
    assert graph["unresolved_relationships"]


def test_typed_relationship_with_matching_scope_still_resolves():
    source = Resource(
        resource_type="aws_subnet", resource_id="subnet-a",
        attributes={"vpc_id": "vpc-1"}, source="aws",
        region="eu-west-2", account_id="111111111111",
    )
    target = Resource(
        resource_type="aws_vpc", resource_id="vpc-1",
        attributes={}, source="aws", region="eu-west-2",
        account_id="111111111111",
    )

    graph = build_resource_graph([source, target])

    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["relationship"] == "vpc_id"
    assert graph["edges"][0]["confidence"] == "high"
