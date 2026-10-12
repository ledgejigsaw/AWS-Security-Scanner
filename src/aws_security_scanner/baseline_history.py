"""Versioned finding history, deterministic baseline diffs, and suppression governance.

Version 1 baselines (a list of fingerprints) remain readable. Version 2 adds
finding metadata and optional suppression metadata. No raw resource configuration
or credential material is stored.
"""
from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Iterable, Any

from aws_security_scanner.models.finding import Finding

BASELINE_VERSION = 2


def finding_fingerprint(finding: Finding) -> str:
    """Stable identity excludes mutable evidence, descriptions, and severity."""
    identity = {
        "check_id": finding.check_id,
        "service": finding.service,
        "resource": finding.resource,
        "region": finding.region,
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _validate_suppression(value: Any, *, context: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"Invalid suppression metadata in {context}: expected an object.")
    allowed = {"reason", "owner", "expires_on"}
    if set(value) - allowed:
        raise ValueError(f"Invalid suppression metadata in {context}: unknown fields.")
    result: dict[str, str] = {}
    for key in ("reason", "owner", "expires_on"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Invalid suppression metadata in {context}: {key} must be non-empty text.")
            result[key] = item.strip()
    if not result.get("reason"):
        raise ValueError(f"Invalid suppression metadata in {context}: reason is required.")
    if result.get("expires_on"):
        try:
            date.fromisoformat(result["expires_on"])
        except ValueError as error:
            raise ValueError(f"Invalid suppression expiry in {context}: use YYYY-MM-DD.") from error
    return result


def load_baseline_records(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load v1 or v2 baseline entries, validating all untrusted JSON fields."""
    baseline_path = Path(path)
    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read finding baseline '{baseline_path}': {error}") from error
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        raise ValueError(f"Unsupported finding baseline format in '{baseline_path}'. Expected version 1 or 2.")
    records: dict[str, dict[str, Any]] = {}
    if payload["version"] == 1:
        fingerprints = payload.get("fingerprints")
        if not isinstance(fingerprints, list) or not all(
            isinstance(item, str) and len(item) == 64 and all(c in "0123456789abcdef" for c in item)
            for item in fingerprints
        ):
            raise ValueError(f"Invalid fingerprints in finding baseline '{baseline_path}'.")
        return {item: {"fingerprint": item, "suppression": None} for item in fingerprints}
    entries = payload.get("findings")
    if not isinstance(entries, list):
        raise ValueError(f"Invalid findings in finding baseline '{baseline_path}'.")
    for index, entry in enumerate(entries):
        context = f"finding baseline '{baseline_path}' entry {index}"
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid entry in {context}: expected an object.")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise ValueError(f"Invalid fingerprint in {context}.")
        suppression = _validate_suppression(entry.get("suppression"), context=context)
        records[fingerprint] = {**entry, "fingerprint": fingerprint, "suppression": suppression}
    return records


def active_baseline_fingerprints(records: dict[str, dict[str, Any]], *, as_of: date | None = None) -> set[str]:
    """Return baseline identities still eligible for suppression on the given date."""
    today = as_of or date.today()
    active = set()
    for fingerprint, record in records.items():
        suppression = record.get("suppression")
        if suppression and suppression.get("expires_on"):
            if date.fromisoformat(suppression["expires_on"]) < today:
                continue
        active.add(fingerprint)
    return active


def write_baseline(
    findings: Iterable[Finding],
    path: str | Path,
    suppressions: dict[str, dict[str, str]] | None = None,
) -> None:
    """Write a deterministic v2 baseline; suppression keys are finding fingerprints."""
    suppressions = suppressions or {}
    entries = []
    seen = set()
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        suppression = _validate_suppression(suppressions.get(fingerprint), context=f"finding {fingerprint}")
        entry = {
            "fingerprint": fingerprint,
            "check_id": finding.check_id,
            "service": finding.service,
            "resource": finding.resource,
            "region": finding.region,
            "severity": finding.severity.value,
            "title": finding.title,
            "suppression": suppression,
        }
        entries.append(entry)
    entries.sort(key=lambda item: item["fingerprint"])
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"version": BASELINE_VERSION, "findings": entries}, indent=2) + "\n", encoding="utf-8")


def diff_findings(current: Iterable[Finding], baseline_records: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Classify findings by identity, not evidence, with deterministic output order."""
    current_by_id = {finding_fingerprint(item): item for item in current}
    baseline_ids = set(baseline_records)
    result: dict[str, list[dict[str, Any]]] = {"new": [], "resolved": [], "unchanged": []}
    for fingerprint in sorted(set(current_by_id) - baseline_ids):
        item = current_by_id[fingerprint]
        result["new"].append({"fingerprint": fingerprint, "check_id": item.check_id, "service": item.service, "resource": item.resource, "region": item.region, "severity": item.severity.value, "title": item.title})
    for fingerprint in sorted(baseline_ids - set(current_by_id)):
        record = baseline_records[fingerprint]
        result["resolved"].append({key: record.get(key) for key in ("fingerprint", "check_id", "service", "resource", "region", "severity", "title")})
    for fingerprint in sorted(baseline_ids & set(current_by_id)):
        item = current_by_id[fingerprint]
        result["unchanged"].append({"fingerprint": fingerprint, "check_id": item.check_id, "service": item.service, "resource": item.resource, "region": item.region, "severity": item.severity.value, "title": item.title})
    return result
