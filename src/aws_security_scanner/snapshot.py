"""Versioned, credential-free snapshots of normalized resource inventory."""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_security_scanner.models.resource import Resource


SNAPSHOT_SCHEMA_VERSION = "1.0.0"
_ROOT_KEYS = {
    "schema_version", "collected_at", "scan_source", "region",
    "resource_count", "resources", "discovery_coverage",
}
_RESOURCE_KEYS = {
    "resource_type", "resource_id", "attributes", "source", "region",
    "relationships", "account_id", "source_file", "source_address",
}
_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "secretstring", "secretbinary", "secretvalue",
    "secretaccesskey", "accesskeysecret", "accesskey", "secretkey", "apitoken", "token", "credential", "privatekey", "sessiontoken",
    "credentialvalue", "authorization", "clientsecret",
}


def _redact(value: Any, key: str | None = None) -> Any:
    if key is not None:
        normalised = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalised in _SENSITIVE_KEYS:
            return _REDACTED
    if isinstance(value, dict):
        return {str(child_key): _redact(child_value, str(child_key)) for child_key, child_value in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def write_resource_snapshot(
    resources: list[Resource],
    output_path: str | Path,
    *,
    scan_source: str,
    region: str | None = None,
    discovery_coverage: list[dict[str, Any]] | None = None,
) -> None:
    """Write an opt-in snapshot without credential-like attribute values."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    resource_items = []
    for resource in resources:
        item = asdict(resource)
        item["attributes"] = _redact(item.get("attributes", {}))
        item["relationships"] = _redact(item.get("relationships"))
        resource_items.append(item)
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "scan_source": scan_source,
        "region": region,
        "resource_count": len(resource_items),
        "resources": resource_items,
        "discovery_coverage": _redact(discovery_coverage) if discovery_coverage is not None else None,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_resource_snapshot(input_path: str | Path) -> list[Resource]:
    """Load a compatible snapshot and reject unknown structure rather than dropping fields."""
    path = Path(input_path)
    try:
        with path.open(encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read resource snapshot '{path}': {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Resource snapshot root must be a JSON object.")
    unknown_root = set(payload) - _ROOT_KEYS
    if unknown_root:
        raise ValueError(f"Resource snapshot contains unsupported top-level fields: {', '.join(sorted(unknown_root))}")
    if payload.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported resource snapshot schema version {payload.get('schema_version')!r}; "
            f"supported version is {SNAPSHOT_SCHEMA_VERSION!r}."
        )
    items = payload.get("resources")
    if not isinstance(items, list):
        raise ValueError("Resource snapshot field 'resources' must be a list.")
    if payload.get("resource_count") != len(items):
        raise ValueError("Resource snapshot resource_count does not match the resources array.")

    resources: list[Resource] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"Resource snapshot resources[{index}] must be an object.")
        unknown = set(item) - _RESOURCE_KEYS
        if unknown:
            raise ValueError(
                f"Resource snapshot resources[{index}] contains unsupported fields: {', '.join(sorted(unknown))}"
            )
        for required in ("resource_type", "resource_id", "attributes", "source"):
            if required not in item:
                raise ValueError(f"Resource snapshot resources[{index}] is missing {required!r}.")
        if not isinstance(item["resource_type"], str) or not isinstance(item["resource_id"], str):
            raise ValueError(f"Resource snapshot resources[{index}] has invalid resource identity.")
        if not isinstance(item["source"], str) or not isinstance(item["attributes"], dict):
            raise ValueError(f"Resource snapshot resources[{index}] has invalid source or attributes.")
        relationships = item.get("relationships")
        if relationships is not None and (
            not isinstance(relationships, dict)
            or not all(isinstance(key, str) and isinstance(value, str) for key, value in relationships.items())
        ):
            raise ValueError(f"Resource snapshot resources[{index}] has invalid relationships.")
        for optional in ("region", "account_id", "source_file", "source_address"):
            if item.get(optional) is not None and not isinstance(item[optional], str):
                raise ValueError(f"Resource snapshot resources[{index}] has invalid {optional!r}.")
        resources.append(Resource(
            resource_type=item["resource_type"],
            resource_id=item["resource_id"],
            attributes=item["attributes"],
            source=item["source"],
            region=item.get("region"),
            relationships=relationships,
            account_id=item.get("account_id"),
            source_file=item.get("source_file"),
            source_address=item.get("source_address"),
        ))
    return resources
