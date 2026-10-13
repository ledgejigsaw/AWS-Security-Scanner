import json

import pytest

from aws_security_scanner.compliance import (
    ComplianceMappingError,
    load_mapping_file,
    validate_mapping_document,
)


def valid_document():
    return {
        "schema_version": 1,
        "framework": {"name": "Example framework", "version": "1"},
        "controls": [
            {
                "control_id": "AC-6",
                "title": "Least Privilege",
                "check_ids": ["IAM-001"],
                "confidence": "direct",
                "rationale": "The check directly evaluates this control objective.",
            }
        ],
    }


def test_validate_mapping_document_accepts_valid_mapping():
    document = valid_document()

    assert validate_mapping_document(document, {"IAM-001"}) == document


def test_validate_mapping_document_rejects_unknown_schema_version():
    document = valid_document()
    document["schema_version"] = 2

    with pytest.raises(ComplianceMappingError, match="schema_version"):
        validate_mapping_document(document)


def test_validate_mapping_document_rejects_unregistered_check_id():
    with pytest.raises(ComplianceMappingError, match="unregistered check ID"):
        validate_mapping_document(valid_document(), {"S3-001"})


def test_validate_mapping_document_rejects_invalid_confidence():
    document = valid_document()
    document["controls"][0]["confidence"] = "guaranteed"

    with pytest.raises(ComplianceMappingError, match="confidence"):
        validate_mapping_document(document)


def test_validate_mapping_document_rejects_duplicate_control_check_pair():
    document = valid_document()
    duplicate = dict(document["controls"][0])
    document["controls"].append(duplicate)

    with pytest.raises(ComplianceMappingError, match="Duplicate mapping"):
        validate_mapping_document(document)


def test_load_mapping_file_reads_and_validates_json(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(valid_document()), encoding="utf-8")

    assert load_mapping_file(path, {"IAM-001"})["framework"]["name"] == "Example framework"


def test_load_mapping_file_reports_invalid_json(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ComplianceMappingError, match="Invalid JSON"):
        load_mapping_file(path)
