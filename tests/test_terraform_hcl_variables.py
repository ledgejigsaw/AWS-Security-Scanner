from pathlib import Path

import pytest

from aws_security_scanner.cli import build_parser, discover_resources
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider


def _bucket(resources, address="aws_s3_bucket.data"):
    return next(resource for resource in resources if resource.source_address == address)


def test_root_tfvars_and_auto_tfvars_precedence_is_deterministic(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "bucket_name" { default = "default-bucket" }\n'
        'resource "aws_s3_bucket" "data" { bucket = var.bucket_name }\n',
        encoding="utf-8",
    )
    (tmp_path / "terraform.tfvars").write_text('bucket_name = "standard-bucket"\n', encoding="utf-8")
    (tmp_path / "10.auto.tfvars").write_text('bucket_name = "auto-first"\n', encoding="utf-8")
    (tmp_path / "20.auto.tfvars").write_text('bucket_name = "auto-last"\n', encoding="utf-8")

    bucket = _bucket(TerraformHCLProvider(tmp_path).discover())
    assert bucket.attributes["bucket"] == "auto-last"
    assert "hcl_unresolved_expressions" not in bucket.attributes


def test_explicit_var_files_override_automatic_files_in_argument_order(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "bucket_name" { default = "default-bucket" }\n'
        'resource "aws_s3_bucket" "data" { bucket = var.bucket_name }\n',
        encoding="utf-8",
    )
    (tmp_path / "terraform.tfvars").write_text('bucket_name = "standard-bucket"\n', encoding="utf-8")
    first = tmp_path / "first.auto.tfvars.json"
    second = tmp_path / "override.json"
    first.write_text('{"bucket_name": "auto-bucket"}', encoding="utf-8")
    second.write_text('{"bucket_name": "explicit-bucket"}', encoding="utf-8")

    bucket = _bucket(TerraformHCLProvider(tmp_path, var_files=[first, second]).discover())
    assert bucket.attributes["bucket"] == "explicit-bucket"


def test_locals_resolve_chained_variable_references_across_files(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "bucket_name" { default = "private-data" }\n'
        'resource "aws_s3_bucket" "data" { bucket = local.final_name }\n',
        encoding="utf-8",
    )
    (tmp_path / "locals.tf").write_text(
        'locals { base_name = var.bucket_name }\n'
        'locals { final_name = local.base_name }\n',
        encoding="utf-8",
    )

    bucket = _bucket(TerraformHCLProvider(tmp_path).discover())
    assert bucket.attributes["bucket"] == "private-data"
    assert "hcl_unresolved_expressions" not in bucket.attributes


def test_local_values_propagate_to_local_module_arguments(tmp_path):
    root = tmp_path / "root"
    child = root / "modules" / "storage"
    child.mkdir(parents=True)
    (root / "main.tf").write_text(
        'locals { bucket_name = "private-module-data" }\n'
        'module "storage" {\n'
        '  source = "./modules/storage"\n'
        '  bucket_name = local.bucket_name\n'
        '}\n',
        encoding="utf-8",
    )
    (child / "main.tf").write_text(
        'variable "bucket_name" { default = "fallback" }\n'
        'resource "aws_s3_bucket" "data" { bucket = var.bucket_name }\n',
        encoding="utf-8",
    )

    bucket = _bucket(TerraformHCLProvider(root).discover(), "module.storage.aws_s3_bucket.data")
    assert bucket.attributes["bucket"] == "private-module-data"


def test_cli_accepts_repeatable_var_files_and_rejects_other_sources(tmp_path):
    first = tmp_path / "first.tfvars"
    second = tmp_path / "second.tfvars"
    args = build_parser().parse_args([
        "--source", "hcl", "--file", str(tmp_path),
        "--var-file", str(first), "--var-file", str(second),
    ])
    assert args.var_file == [first, second]
    with pytest.raises(ValueError, match="--var-file can only be used"):
        discover_resources("terraform", tmp_path / "plan.json", var_files=[first])
