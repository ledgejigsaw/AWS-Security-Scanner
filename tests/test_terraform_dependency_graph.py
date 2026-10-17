from pathlib import Path

from aws_security_scanner.cli import run_scan
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider


def test_hcl_dependency_graph_resolves_cross_file_edges_deterministically(tmp_path):
    first = tmp_path / "a.tf"
    second = tmp_path / "z.tf"
    first.write_text(
        'resource "aws_s3_bucket" "data" { bucket = "known-data" }\n',
        encoding="utf-8",
    )
    second.write_text(
        'resource "aws_s3_bucket_versioning" "data" { bucket = aws_s3_bucket.data.id }\n',
        encoding="utf-8",
    )

    provider = TerraformHCLProvider(tmp_path)
    resources = provider.discover()
    graph = provider.dependency_graph

    assert graph is not None
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.edges[0].source == "aws_s3_bucket_versioning.data"
    assert graph.edges[0].target == "aws_s3_bucket.data"
    assert graph.unresolved == ()
    assert graph.cycle_nodes == ()
    assert not any(item.attributes.get("hcl_diagnostic") == "dependency_reference_unresolved" for item in resources)


def test_hcl_dependency_graph_reports_missing_resource_targets(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = aws_s3_bucket.missing.bucket }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(tmp_path).discover()
    diagnostic = next(
        item for item in resources
        if item.attributes.get("hcl_diagnostic") == "dependency_reference_unresolved"
    )
    assert "target_not_discovered" in diagnostic.attributes["hcl_diagnostic_reason"]
    findings = run_scan("hcl", tmp_path)
    assert any(item.check_id == "IAC-HCL-004" for item in findings)


def test_hcl_dependency_graph_reports_directed_cycles(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" { bucket = aws_s3_bucket.b.bucket }\n'
        'resource "aws_s3_bucket" "b" { bucket = aws_s3_bucket.a.bucket }\n',
        encoding="utf-8",
    )

    provider = TerraformHCLProvider(tmp_path)
    resources = provider.discover()
    assert set(provider.dependency_graph.cycle_nodes) == {
        "aws_s3_bucket.a", "aws_s3_bucket.b",
    }
    assert sum(item.attributes.get("hcl_diagnostic") == "dependency_cycle" for item in resources) == 2
    assert any(item.check_id == "IAC-HCL-005" for item in run_scan("hcl", tmp_path))


def test_hcl_dependency_graph_is_empty_for_resources_without_references(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = "independent-data" }\n',
        encoding="utf-8",
    )
    provider = TerraformHCLProvider(tmp_path)
    provider.discover()
    assert provider.dependency_graph.edges == ()
    assert provider.dependency_graph.unresolved == ()
    assert provider.dependency_graph.cycle_nodes == ()


def test_hcl_cycle_detection_excludes_path_between_two_cycles(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" { bucket = aws_s3_bucket.b.bucket }\n'
        'resource "aws_s3_bucket" "b" { bucket = aws_s3_bucket.a.bucket\n force_destroy = aws_s3_bucket.bridge.id }\n'
        'resource "aws_s3_bucket" "bridge" { bucket = aws_s3_bucket.c.bucket }\n'
        'resource "aws_s3_bucket" "c" { bucket = aws_s3_bucket.d.bucket }\n'
        'resource "aws_s3_bucket" "d" { bucket = aws_s3_bucket.c.bucket }\n',
        encoding="utf-8",
    )
    provider = TerraformHCLProvider(tmp_path)
    provider.discover()

    assert set(provider.dependency_graph.cycle_nodes) == {
        "aws_s3_bucket.a",
        "aws_s3_bucket.b",
        "aws_s3_bucket.c",
        "aws_s3_bucket.d",
    }
    assert "aws_s3_bucket.bridge" not in provider.dependency_graph.cycle_nodes


def test_hcl_cycle_detection_identifies_self_loop_only():
    from aws_security_scanner.terraform_dependency_graph import _find_cycle_nodes

    assert _find_cycle_nodes({"a": ["a"], "b": ["a"], "c": ["b"]}) == {"a"}
