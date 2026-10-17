from pathlib import Path

import pytest

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



def test_hcl_provider_preserves_multiple_resource_references_in_lists(tmp_path):
    source = tmp_path / "network.tf"
    source.write_text(
        '''
resource "aws_subnet" "private" {
  vpc_id = "vpc-123"
}

resource "aws_security_group" "web" {
  name = "web"
}

resource "aws_security_group" "app" {
  name = "app"
}

resource "aws_instance" "application" {
  subnet_id = aws_subnet.private.id
  vpc_security_group_ids = [
    aws_security_group.web.id,
    aws_security_group.app.id,
  ]
}
''',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    instance = next(item for item in resources if item.resource_type == "aws_instance")

    assert instance.relationships == {
        "subnet_id": "aws_subnet.private",
        "vpc_security_group_ids[0]": "aws_security_group.web",
        "vpc_security_group_ids[1]": "aws_security_group.app",
    }


def test_hcl_provider_preserves_nested_relationship_paths(tmp_path):
    source = tmp_path / "routes.tf"
    source.write_text(
        '''
resource "aws_route_table" "private" {
  vpc_id = "vpc-123"
  route {
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = "vpc-123"
}
''',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    route_table = next(item for item in resources if item.resource_type == "aws_route_table")

    assert route_table.relationships == {
        "route[0].gateway_id": "aws_internet_gateway.main",
    }



def test_hcl_expands_local_module_and_propagates_literal_inputs(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "storage"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "storage" {\n'
        '  source = "./modules/storage"\n'
        '  bucket_name = "production-data"\n'
        '}\n',
        encoding="utf-8",
    )
    (child / "variables.tf").write_text(
        'variable "bucket_name" {\n'
        '  type = string\n'
        '  default = "fallback-data"\n'
        '}\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = var.bucket_name\n'
        '}\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    bucket = next(item for item in resources if item.source_address == "module.storage.aws_s3_bucket.data")
    assert bucket.attributes["bucket"] == "production-data"
    assert "hcl_unresolved_expressions" not in bucket.attributes
    assert not any(item.attributes.get("hcl_diagnostic") == "module_not_expanded" for item in resources)


def test_hcl_local_module_uses_variable_default_when_input_omitted(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "storage"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "storage" { source = "./modules/storage" }\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'variable "bucket_name" { default = "default-data" }\n'
        'resource "aws_s3_bucket" "data" { bucket = var.bucket_name }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    bucket = next(item for item in resources if item.source_address == "module.storage.aws_s3_bucket.data")
    assert bucket.attributes["bucket"] == "default-data"


def test_hcl_nested_local_modules_are_expanded_with_distinct_addresses(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "network"
    grandchild = child / "modules" / "bucket"
    grandchild.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "network" { source = "./modules/network" }\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'module "bucket" { source = "./modules/bucket" }\n',
        encoding="utf-8",
    )
    (grandchild / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = "nested-data" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    assert any(item.source_address == "module.network.module.bucket.aws_s3_bucket.data" for item in resources)
    assert not any(item.attributes.get("hcl_diagnostic") == "module_not_expanded" for item in resources)


def test_hcl_remote_module_is_not_downloaded_and_has_reason(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text(
        'module "remote" { source = "terraform-aws-modules/vpc/aws" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(source).discover()
    module = next(item for item in resources if item.source_address == "module.remote")
    assert module.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "not downloaded or executed" in module.attributes["hcl_diagnostic_reason"]


def test_hcl_local_module_outside_scan_root_is_not_followed(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.tf").write_text(
        'resource "aws_s3_bucket" "outside" { bucket = "outside-data" }\n',
        encoding="utf-8",
    )
    (root / "main.tf").write_text(
        'module "escape" { source = "../outside" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    module = next(item for item in resources if item.source_address == "module.escape")
    assert module.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "outside the selected scan root" in module.attributes["hcl_diagnostic_reason"]


def test_hcl_local_module_cycle_is_reported_without_recursing_forever(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "child"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "child" { source = "./modules/child" }\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'module "back" { source = "../../" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    cycle = next(item for item in resources if item.source_address == "module.child.module.back")
    assert cycle.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "cycle" in cycle.attributes["hcl_diagnostic_reason"]


def test_hcl_unknown_module_input_does_not_fall_back_to_child_default(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "storage"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "storage" {\n'
        '  source = "./modules/storage"\n'
        '  bucket_name = var.root_bucket\n'
        '}\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'variable "bucket_name" { default = "fallback-data" }\n'
        'resource "aws_s3_bucket" "data" { bucket = var.bucket_name }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    bucket = next(item for item in resources if item.source_address == "module.storage.aws_s3_bucket.data")
    assert "fallback-data" != bucket.attributes["bucket"]
    assert bucket.attributes["hcl_unresolved_expressions"]


def test_hcl_module_count_is_not_expanded_as_single_instance(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "network"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'module "network" { source = "./modules/network" count = 2 }\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(root).discover()
    module = next(item for item in resources if item.source_address == "module.network")
    assert module.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "cardinality" in module.attributes["hcl_diagnostic_reason"]
    assert not any(item.source_address == "module.network.aws_vpc.main" for item in resources)


def test_hcl_module_outside_scan_root_expands_when_explicitly_trusted(tmp_path):
    repository = tmp_path / "terraform-repo"
    example = repository / "examples" / "complete"
    module = repository / "modules" / "storage"
    example.mkdir(parents=True)
    module.mkdir(parents=True)
    (example / "main.tf").write_text(
        'module "storage" { source = "../../modules/storage" }\n',
        encoding="utf-8",
    )
    (module / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" { bucket = "sensitive-data" }\n',
        encoding="utf-8",
    )

    default_resources = TerraformHCLProvider(example).discover()
    diagnostic = next(item for item in default_resources if item.source_address == "module.storage")
    assert diagnostic.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "trusted module roots" in diagnostic.attributes["hcl_diagnostic_reason"]

    trusted_resources = TerraformHCLProvider(example, module_roots=[repository]).discover()
    assert any(item.source_address == "module.storage.aws_s3_bucket.data" for item in trusted_resources)
    assert not any(item.attributes.get("hcl_diagnostic") == "module_not_expanded" for item in trusted_resources)


def test_hcl_trusted_module_root_does_not_allow_escape_outside_trusted_root(tmp_path):
    repository = tmp_path / "terraform-repo"
    example = repository / "examples" / "complete"
    module = repository / "modules" / "storage"
    outside = tmp_path / "outside"
    example.mkdir(parents=True)
    module.mkdir(parents=True)
    outside.mkdir()
    (example / "main.tf").write_text(
        'module "storage" { source = "../../modules/storage" }\n',
        encoding="utf-8",
    )
    (module / "main.tf").write_text(
        'module "escape" { source = "../../../outside" }\n',
        encoding="utf-8",
    )
    (outside / "main.tf").write_text(
        'resource "aws_s3_bucket" "outside" { bucket = "outside-data" }\n',
        encoding="utf-8",
    )

    resources = TerraformHCLProvider(example, module_roots=[repository]).discover()
    escape = next(item for item in resources if item.source_address == "module.storage.module.escape")
    assert escape.attributes["hcl_diagnostic"] == "module_not_expanded"
    assert "outside the selected scan root and all explicitly trusted module roots" in escape.attributes["hcl_diagnostic_reason"]


def test_hcl_trusted_module_root_must_be_an_existing_directory(tmp_path):
    source = tmp_path / "main.tf"
    source.write_text('resource "aws_s3_bucket" "data" { bucket = "data" }\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Trusted Terraform module root"):
        TerraformHCLProvider(source, module_roots=[tmp_path / "missing"])
