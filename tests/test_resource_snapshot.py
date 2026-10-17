import json

import pytest

from aws_security_scanner.cli import build_parser, run_scan
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.snapshot import (
    SNAPSHOT_SCHEMA_VERSION,
    load_resource_snapshot,
    write_resource_snapshot,
)


def test_snapshot_round_trip_preserves_resource_identity_and_redacts_sensitive_values(tmp_path):
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="example",
        attributes={
            "public": True,
            "password": "synthetic-password",
            "SecretString": "synthetic-secret",
            "api_token": "synthetic-token",
            "nested": {"private_key": "synthetic-private-key"},
        },
        source="fixture",
        region="eu-west-2",
        relationships={"logging.target": "aws_s3_bucket.logs"},
        account_id="111111111111",
        source_file="main.tf",
        source_address="aws_s3_bucket.example",
    )
    path = tmp_path / "inventory.json"

    write_resource_snapshot([resource], path, scan_source="fixture", region="eu-west-2")
    payload = json.loads(path.read_text(encoding="utf-8"))
    loaded = load_resource_snapshot(path)

    assert payload["schema_version"] == SNAPSHOT_SCHEMA_VERSION
    assert payload["resource_count"] == 1
    assert loaded[0].resource_id == "example"
    assert loaded[0].relationships == {"logging.target": "aws_s3_bucket.logs"}
    assert loaded[0].source_address == "aws_s3_bucket.example"
    serialized = json.dumps(payload)
    assert "synthetic-password" not in serialized
    assert "synthetic-secret" not in serialized
    assert "synthetic-token" not in serialized
    assert "synthetic-private-key" not in serialized
    assert "[REDACTED]" in serialized


def test_snapshot_loader_rejects_unknown_fields_and_versions(tmp_path):
    path = tmp_path / "inventory.json"
    base = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "collected_at": "2026-10-17T00:00:00+00:00",
        "scan_source": "fixture",
        "region": None,
        "resource_count": 0,
        "resources": [],
        "discovery_coverage": None,
    }
    path.write_text(json.dumps({**base, "unexpected": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported top-level fields"):
        load_resource_snapshot(path)

    path.write_text(json.dumps({**base, "schema_version": "99.0.0"}), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported resource snapshot schema version"):
        load_resource_snapshot(path)


def test_snapshot_loader_rejects_unknown_resource_fields(tmp_path):
    path = tmp_path / "inventory.json"
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "collected_at": "2026-10-17T00:00:00+00:00",
        "scan_source": "fixture",
        "region": None,
        "resource_count": 1,
        "resources": [{
            "resource_type": "aws_s3_bucket",
            "resource_id": "example",
            "attributes": {},
            "source": "fixture",
            "unexpected_resource_field": "not silently ignored",
        }],
        "discovery_coverage": None,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_resource_snapshot(path)


def test_snapshot_source_is_supported_by_cli_and_replays_rules_offline(tmp_path):
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="public-bucket",
        attributes={"public": True},
        source="fixture",
        region="eu-west-2",
    )
    snapshot = tmp_path / "inventory.json"
    write_resource_snapshot([resource], snapshot, scan_source="fixture", region="eu-west-2")

    parser = build_parser()
    args = parser.parse_args(["--source", "snapshot", "--file", str(snapshot)])
    assert args.source == "snapshot"

    findings = run_scan("snapshot", snapshot)
    assert any(item.check_id == "S3-001" for item in findings)
