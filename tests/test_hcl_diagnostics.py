from aws_security_scanner.cli import run_scan
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider


def test_hcl_data_sources_are_reported_as_unexpanded_diagnostics(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        'data "aws_s3_bucket" "existing" { bucket = "existing-bucket" }\n'
        'resource "aws_s3_bucket" "target" { bucket = "target-bucket" count = 1 }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    data_source = next(item for item in resources if item.resource_id == "data.aws_s3_bucket.existing")
    target = next(item for item in resources if item.resource_id == "target")

    assert data_source.resource_type == "terraform_hcl_unsupported"
    assert data_source.attributes["hcl_diagnostic"] == "data_source_not_evaluated"
    assert "hcl_unresolved_expressions" not in data_source.attributes
    assert data_source.source_file == str(source)
    assert data_source.source_address == "data.aws_s3_bucket.existing"
    assert target.attributes["hcl_unresolved_expressions"]
    assert any("count" in value for value in target.attributes["hcl_unresolved_expressions"])


def test_hcl_dynamic_blocks_are_explicitly_marked_unresolved(tmp_path):
    source = tmp_path / "dynamic.tf"
    source.write_text(
        'resource "aws_s3_bucket" "example" {\n'
        '  bucket = "example-bucket"\n'
        '  dynamic "lifecycle_rule" {\n'
        '    for_each = var.rules\n'
        '    content { enabled = true }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )

    resource = TerraformHCLProvider(source).discover()[0]
    assert any("dynamic" in value for value in resource.attributes["hcl_unresolved_expressions"])


def test_malformed_hcl_is_reported_as_value_error(tmp_path):
    source = tmp_path / "broken.tf"
    source.write_text('resource "aws_s3_bucket" "broken" { bucket = ', encoding="utf-8")

    try:
        TerraformHCLProvider(source).discover()
    except ValueError as error:
        assert "Unable to parse Terraform HCL file" in str(error)
    else:
        raise AssertionError("Malformed HCL must fail with a contextual ValueError")


def test_hcl_provider_scans_all_top_level_files_as_one_module(tmp_path):
    module = tmp_path / "module"
    module.mkdir()
    first = module / "main.tf"
    second = module / "network.tf"
    first.write_text(
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n',
        encoding="utf-8",
    )
    second.write_text(
        'resource "aws_subnet" "private" {\n  vpc_id = aws_vpc.main.id\n  cidr_block = "10.0.1.0/24"\n}\n',
        encoding="utf-8",
    )
    nested = module / "examples" / "other"
    nested.mkdir(parents=True)
    (nested / "other.tf").write_text(
        'resource "aws_s3_bucket" "unrelated" { bucket = "not-part-of-this-module" }\n',
        encoding="utf-8",
    )
    generated = module / ".terraform"
    generated.mkdir()
    (generated / "generated.tf").write_text(
        'resource "aws_s3_bucket" "generated" { bucket = "not-scanned" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(module).discover()
    by_address = {item.source_address: item for item in resources}
    assert set(by_address) == {"aws_vpc.main", "aws_subnet.private"}
    assert by_address["aws_vpc.main"].source_file == str(first)
    assert by_address["aws_subnet.private"].source_file == str(second)
    assert by_address["aws_subnet.private"].relationships["vpc_id"] == "aws_vpc.main"


def test_hcl_provider_rejects_empty_module_directory(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="No Terraform HCL files"):
        TerraformHCLProvider(tmp_path).discover()


def test_hcl_provider_rejects_missing_path(tmp_path):
    import pytest

    with pytest.raises(ValueError, match="does not exist"):
        TerraformHCLProvider(tmp_path / "missing").discover()


def test_hcl_data_source_gets_distinct_cli_diagnostic(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text('data "aws_availability_zones" "available" {}\n', encoding="utf-8")
    findings = run_scan("hcl", source)
    diagnostic = next(item for item in findings if item.resource == "data.aws_availability_zones.available")
    assert diagnostic.check_id == "IAC-HCL-003"
    assert diagnostic.title == "Terraform data source was not evaluated"
    assert diagnostic.source_file == str(source)
    assert diagnostic.source_address == "data.aws_availability_zones.available"
