"""Export a deterministic machine-readable inventory of registered rules.

Run from a source checkout with:
    python scripts/export_rule_inventory.py --output reports/rule-inventory.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from aws_security_scanner.rules.registry import get_all_rules  # noqa: E402


def build_inventory() -> dict[str, Any]:
    """Return rule metadata sorted by stable check ID."""
    rules = []
    for rule in get_all_rules():
        metadata = getattr(rule, "metadata", None)
        if metadata is None:
            raise ValueError(f"Registered rule {getattr(rule, '__name__', '<unknown>')} has no metadata.")
        rules.append({
            "check_id": metadata.check_id,
            "service": metadata.service,
            "resource_type": metadata.resource_type,
            "severity": metadata.severity.value,
            "category": metadata.category,
            "title": metadata.title,
            "description": metadata.description,
            "remediation": metadata.remediation,
        })
    rules.sort(key=lambda item: item["check_id"])
    ids = [item["check_id"] for item in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("Rule registry contains duplicate check IDs.")
    return {
        "schema_version": "1.0.0",
        "inventory_kind": "registered_rule_metadata",
        "rule_count": len(rules),
        "rules": rules,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Output JSON path; defaults to stdout.")
    args = parser.parse_args()
    rendered = json.dumps(build_inventory(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
