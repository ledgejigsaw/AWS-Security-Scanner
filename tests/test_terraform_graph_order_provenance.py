from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider


def test_root_graph_is_stable_when_files_are_created_in_different_orders(tmp_path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()

    bucket = 'resource "aws_s3_bucket" "data" { bucket = "known-data" }\n'
    versioning = 'resource "aws_s3_bucket_versioning" "data" { bucket = aws_s3_bucket.data.id }\n'
    for name, text in [("a.tf", bucket), ("z.tf", versioning)]:
        (left / name).write_text(text, encoding="utf-8")
    for name, text in [("z.tf", versioning), ("a.tf", bucket)]:
        (right / name).write_text(text, encoding="utf-8")

    first = TerraformHCLProvider(left)
    first.discover()
    second = TerraformHCLProvider(right)
    second.discover()

    assert [(node["address"], node["resource_type"]) for node in first.dependency_graph.nodes] == [(node["address"], node["resource_type"]) for node in second.dependency_graph.nodes]
    assert first.dependency_graph.edges == second.dependency_graph.edges
    assert [(edge["source"], edge["attribute"], edge["target"], edge["reason"]) for edge in first.dependency_graph.unresolved] == [(edge["source"], edge["attribute"], edge["target"], edge["reason"]) for edge in second.dependency_graph.unresolved]


def test_graph_preserves_file_provenance_for_each_resource_node(tmp_path):
    (tmp_path / "network.tf").write_text(
        'resource "aws_s3_bucket" "logs" { bucket = "known-logs" }\n',
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "logs" { bucket = aws_s3_bucket.logs.id }\n',
        encoding="utf-8",
    )
    provider = TerraformHCLProvider(tmp_path)
    provider.discover()

    nodes = {item["address"]: item for item in provider.dependency_graph.nodes}
    assert nodes["aws_s3_bucket.logs"]["source_file"].endswith("network.tf")
    assert nodes["aws_s3_bucket_versioning.logs"]["source_file"].endswith("versioning.tf")
