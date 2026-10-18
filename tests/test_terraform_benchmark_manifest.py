"""Validation tests for the offline Terraform benchmark manifest."""
import pytest

from scripts.benchmark_terraform_corpus import _validate_manifest


def valid_manifest(tmp_path):
    (tmp_path / "case").mkdir(exist_ok=True)
    return {
        "schema_version": "1.0.0",
        "cases": [{
            "id": "secure-case",
            "path": "case",
            "expected_check_ids": [],
            "expected_status": "complete",
            "class": "secure",
            "notes": "control fixture",
        }],
    }


def test_manifest_accepts_valid_case(tmp_path):
    manifest = valid_manifest(tmp_path)
    cases = _validate_manifest(manifest, tmp_path)
    assert [case["id"] for case in cases] == ["secure-case"]


def test_manifest_rejects_duplicate_case_ids(tmp_path):
    manifest = valid_manifest(tmp_path)
    manifest["cases"].append(dict(manifest["cases"][0]))
    with pytest.raises(ValueError, match="Duplicate.*case id"):
        _validate_manifest(manifest, tmp_path)


def test_manifest_rejects_invalid_expected_ids_and_status(tmp_path):
    manifest = valid_manifest(tmp_path)
    manifest["cases"][0]["expected_check_ids"] = ["S3-001", 7]
    with pytest.raises(ValueError, match="expected_check_ids"):
        _validate_manifest(manifest, tmp_path)
    manifest = valid_manifest(tmp_path)
    manifest["cases"][0]["expected_status"] = "clean"
    with pytest.raises(ValueError, match="expected_status"):
        _validate_manifest(manifest, tmp_path)


def test_manifest_rejects_paths_outside_root(tmp_path):
    manifest = valid_manifest(tmp_path)
    manifest["cases"][0]["path"] = "../outside"
    with pytest.raises(ValueError, match="escapes repository root"):
        _validate_manifest(manifest, tmp_path)


def test_manifest_rejects_missing_case_path(tmp_path):
    manifest = valid_manifest(tmp_path)
    manifest["cases"][0]["path"] = "missing"
    with pytest.raises(ValueError, match="does not exist"):
        _validate_manifest(manifest, tmp_path)


def test_manifest_rejects_duplicate_expected_check_ids(tmp_path):
    manifest = valid_manifest(tmp_path)
    manifest["cases"][0]["expected_check_ids"] = ["S3-001", "S3-001"]
    with pytest.raises(ValueError, match="duplicate expected check IDs"):
        _validate_manifest(manifest, tmp_path)
