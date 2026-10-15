from pathlib import Path

from aws_security_scanner.cli import build_parser, run_scan
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider
from aws_security_scanner.models.resource import Resource


def test_hcl_provider_loads_resources_and_resolves_resource_references(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        '''
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  region = "eu-west-2"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "web" {
  name = "web"
  description = "web security group"
}
''',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    assert {item.resource_type for item in resources} == {
        "aws_s3_bucket",
        "aws_s3_bucket_versioning",
        "aws_security_group",
    }
    versioning = next(item for item in resources if item.resource_type == "aws_s3_bucket_versioning")
    assert versioning.relationships["bucket"] == "aws_s3_bucket.data"
    assert versioning.attributes["versioning_configuration"] == {"status": "Enabled"}

    normalised = aggregate_s3_resources(resources)
    assert {item.resource_type for item in normalised} == {
        "aws_s3_bucket",
        "aws_security_group",
    }
    bucket = next(item for item in normalised if item.resource_type == "aws_s3_bucket")
    assert bucket.attributes["versioning_configuration"] == {"status": "Enabled"}
    assert bucket.attributes["versioning"] is True


def test_hcl_provider_marks_unresolved_expressions_and_module_blocks(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        '''
variable "bucket_name" {
  type = string
}

resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
  tags = {
    owner = var.owner
  }
}

module "network" {
  source = "./modules/network"
}
''',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    bucket = next(item for item in resources if item.resource_type == "aws_s3_bucket")
    module = next(item for item in resources if item.resource_type == "terraform_hcl_unsupported")

    assert bucket.attributes["hcl_unresolved_expressions"]
    assert module.resource_id == "module.network"
    assert module.attributes["hcl_diagnostic"] == "module_not_expanded"


def test_hcl_cli_source_and_diagnostics_are_opt_in(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        '''
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name
}
''',
        encoding="utf-8",
    )

    args = build_parser().parse_args(["--source", "hcl", "--file", str(source)])
    assert args.source == "hcl"

    findings = run_scan("hcl", source)
    diagnostics = [finding for finding in findings if finding.check_id == "IAC-HCL-001"]
    assert len(diagnostics) == 1
    assert diagnostics[0].severity.value == "INFO"
    assert "unresolved expressions" in diagnostics[0].title


def test_terraform_normalisation_preserves_non_s3_resources():
    non_s3 = Resource(
        resource_type="aws_instance",
        resource_id="web",
        attributes={"instance_type": "t3.micro"},
        source="terraform",
    )
    assert aggregate_s3_resources([non_s3]) == [non_s3]
