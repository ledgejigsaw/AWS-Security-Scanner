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
