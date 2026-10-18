import pytest

from aws_security_scanner.terraform_external_modules import validate_external_module_source


def test_registry_source_requires_exact_version():
    result = validate_external_module_source("terraform-aws-modules/vpc/aws", version="5.8.1")
    assert result.kind == "registry"
    assert result.immutable_ref == "5.8.1"


def test_git_source_requires_full_commit_sha_and_https():
    sha = "a" * 40
    result = validate_external_module_source("git::https://github.com/example/network.git?ref=" + sha)
    assert result.kind == "git"
    assert result.immutable_ref == sha


@pytest.mark.parametrize(
    ("source", "version"),
    [
        ("../private-module", None),
        ("/tmp/module", None),
        ("terraform-aws-modules/vpc/aws", None),
        ("terraform-aws-modules/vpc/aws", "5.8"),
        ("git::http://github.com/example/module.git?ref=" + "a" * 40, None),
        ("git::https://github.com/example/module.git?ref=main", None),
        ("git::https://user:token@github.com/example/module.git?ref=" + "a" * 40, None),
        ("git::https://gitlab.com/example/module.git?ref=" + "a" * 40, None),
    ],
)
def test_external_source_rejects_unpinned_or_unsafe_values(source, version):
    with pytest.raises(ValueError):
        validate_external_module_source(source, version=version)


def test_registry_version_rejects_leading_zero_components():
    with pytest.raises(ValueError, match="exact"):
        validate_external_module_source("terraform-aws-modules/vpc/aws", version="05.8.1")
