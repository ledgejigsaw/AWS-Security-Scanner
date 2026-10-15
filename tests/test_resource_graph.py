import json

from aws_security_scanner.cli import build_parser
from aws_security_scanner.graph import build_resource_graph, write_resource_graph
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource


def test_graph_links_known_relationships_and_findings_without_exporting_attributes():
    bucket = Resource(
        resource_type="aws_s3_bucket",
        resource_id="data-bucket",
        attributes={"secret_policy_document": "DO_NOT_EXPORT"},
        source="terraform",
        region="eu-west-2",
    )
    versioning = Resource(
        resource_type="aws_s3_bucket_versioning",
        resource_id="data-versioning",
        attributes={"versioning_configuration": {"status": "Enabled"}},
        source="terraform",
        region="eu-west-2",
        relationships={"bucket": "aws_s3_bucket.data-bucket"},
    )
    finding = Finding(
        check_id="S3-001",
        severity=Severity.CRITICAL,
        service="S3",
        resource="data-bucket",
        title="Public bucket",
        description="Example",
        remediation="Block public access",
        region="eu-west-2",
    )

    graph = build_resource_graph([versioning, bucket], [finding])

    assert len(graph["nodes"]) == 2
    assert graph["edges"] == [
        {
            "source": next(n["id"] for n in graph["nodes"] if n["resource_id"] == "data-versioning"),
            "target": next(n["id"] for n in graph["nodes"] if n["resource_id"] == "data-bucket"),
            "relationship": "bucket",
            "provenance": "terraform_static_reference",
            "confidence": "high",
        }
    ]
    bucket_node = next(n for n in graph["nodes"] if n["resource_id"] == "data-bucket")
    assert bucket_node["findings"] == [{"check_id": "S3-001", "severity": "CRITICAL"}]
    assert "DO_NOT_EXPORT" not in json.dumps(graph)
    assert "secret_policy_document" not in json.dumps(graph)


def test_graph_records_unresolved_relationship_as_unknown_not_as_missing_edge():
    resource = Resource(
        resource_type="aws_instance",
        resource_id="web",
        attributes={},
        source="terraform",
        relationships={"subnet_id": "${aws_subnet.private.id}"},
    )
    graph = build_resource_graph([resource])
    assert graph["edges"] == []
    assert graph["unresolved_relationships"][0]["status"] == "unknown"
    assert graph["unresolved_relationships"][0]["reference"] == "<unresolved-expression>"


def test_graph_output_is_deterministic_and_write_creates_parent_directory(tmp_path):
    resources = [
        Resource("aws_s3_bucket", "b", {}, "terraform"),
        Resource("aws_s3_bucket", "a", {}, "terraform"),
    ]
    first = build_resource_graph(resources)
    second = build_resource_graph(list(reversed(resources)))
    assert first == second

    output = tmp_path / "nested" / "graph.json"
    write_resource_graph(resources, [], output)
    assert json.loads(output.read_text(encoding="utf-8")) == first


def test_cli_accepts_optional_graph_output():
    args = build_parser().parse_args([
        "--source", "terraform",
        "--file", "tests/fixtures/terraform/realistic_s3.json",
        "--graph-output", "reports/graph.json",
    ])
    assert str(args.graph_output) == "reports/graph.json"
