"""Load and validate versioned security-check-to-framework mappings.

Mappings are reporting metadata only. They do not establish compliance with a
framework or replace the framework's full assessment procedures.
"""

import json
from pathlib import Path
from typing import Any, Iterable


MAPPING_SCHEMA_VERSION = 1
VALID_CONFIDENCE = {"direct", "partial", "contextual"}


class ComplianceMappingError(ValueError):
    """Raised when a compliance mapping document is invalid."""


def validate_mapping_document(
    document: Any,
    registered_check_ids: Iterable[str] | None = None,
) -> dict:
    """Validate mapping structure and, optionally, registered check references.

    The accepted format is intentionally validated in Python rather than
    requiring a new runtime dependency.
    """
    if not isinstance(document, dict):
        raise ComplianceMappingError("Mapping document must be a JSON object.")

    if document.get("schema_version") != MAPPING_SCHEMA_VERSION:
        raise ComplianceMappingError(
            f"schema_version must be {MAPPING_SCHEMA_VERSION}."
        )

    framework = document.get("framework")
    if not isinstance(framework, dict):
        raise ComplianceMappingError("'framework' must be an object.")

    for field in ("name", "version"):
        if not isinstance(framework.get(field), str) or not framework[field].strip():
            raise ComplianceMappingError(
                f"'framework.{field}' must be a non-empty string."
            )

    controls = document.get("controls")
    if not isinstance(controls, list):
        raise ComplianceMappingError("'controls' must be a list.")

    known_ids = set(registered_check_ids) if registered_check_ids is not None else None
    seen_pairs: set[tuple[str, str]] = set()

    for index, control in enumerate(controls):
        prefix = f"controls[{index}]"
        if not isinstance(control, dict):
            raise ComplianceMappingError(f"{prefix} must be an object.")

        for field in ("control_id", "title", "rationale"):
            if not isinstance(control.get(field), str) or not control[field].strip():
                raise ComplianceMappingError(
                    f"{prefix}.{field} must be a non-empty string."
                )

        confidence = control.get("confidence")
        if confidence not in VALID_CONFIDENCE:
            options = ", ".join(sorted(VALID_CONFIDENCE))
            raise ComplianceMappingError(
                f"{prefix}.confidence must be one of: {options}."
            )

        check_ids = control.get("check_ids")
        if not isinstance(check_ids, list) or not check_ids:
            raise ComplianceMappingError(
                f"{prefix}.check_ids must be a non-empty list."
            )

        local_ids: set[str] = set()
        for check_id in check_ids:
            if not isinstance(check_id, str) or not check_id.strip():
                raise ComplianceMappingError(
                    f"{prefix}.check_ids must contain non-empty strings."
                )
            if check_id in local_ids:
                raise ComplianceMappingError(
                    f"{prefix} contains duplicate check ID {check_id!r}."
                )
            local_ids.add(check_id)

            if known_ids is not None and check_id not in known_ids:
                raise ComplianceMappingError(
                    f"{prefix} references unregistered check ID {check_id!r}."
                )

            pair = (control["control_id"], check_id)
            if pair in seen_pairs:
                raise ComplianceMappingError(
                    f"Duplicate mapping for control {pair[0]!r} and check {pair[1]!r}."
                )
            seen_pairs.add(pair)

    return document


def load_mapping_file(
    path: str | Path,
    registered_check_ids: Iterable[str] | None = None,
) -> dict:
    """Read and validate a mapping JSON file."""
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComplianceMappingError(
            f"Unable to read compliance mapping file: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ComplianceMappingError(
            f"Invalid JSON in compliance mapping file {path}: {exc.msg}"
        ) from exc

    return validate_mapping_document(document, registered_check_ids)



def mappings_for_check(document: dict | None, check_id: str) -> list[dict[str, str]]:
    """Return framework mappings for a check ID, preserving source rationale."""
    if document is None:
        return []
    mappings = []
    for control in document["controls"]:
        if check_id in control["check_ids"]:
            mappings.append({
                "control_id": control["control_id"],
                "title": control["title"],
                "confidence": control["confidence"],
                "rationale": control["rationale"],
            })
    return mappings


def framework_metadata(document: dict | None) -> dict | None:
    """Return the framework identity and limitation notice for report metadata."""
    if document is None:
        return None
    framework = document["framework"]
    return {
        "name": framework["name"],
        "version": framework["version"],
        "notice": document.get(
            "mapping_notice",
            "Mappings are indicative only and do not establish compliance.",
        ),
    }
