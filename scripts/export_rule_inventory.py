"""Export a deterministic machine-readable inventory of registered rules.

Run from a source checkout with:
    python scripts/export_rule_inventory.py --output reports/rule-inventory.json
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from aws_security_scanner.rules.registry import get_all_rules  # noqa: E402


def _rule_source(rule: Any) -> tuple[set[str], str | None]:
    """Infer attribute keys and source file from a rule function without executing it."""
    import inspect
    try:
        source_path = Path(inspect.getsourcefile(rule) or "")
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, TypeError):
        return set(), None
    target = next((node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == getattr(rule, "__name__", None)), None)
    if target is None:
        return set(), str(source_path) if source_path else None
    keys: set[str] = set()
    for node in ast.walk(target):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            keys.add(node.args[0].value)
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            keys.add(node.slice.value)
    try:
        relative = str(source_path.relative_to(_REPO_ROOT))
    except ValueError:
        relative = str(source_path)
    return keys, relative


def _test_references(check_id: str) -> list[str]:
    """List test files that mention an ID; this is not proof of branch coverage."""
    result = []
    test_root = _REPO_ROOT / "tests"
    if test_root.exists():
        for path in sorted(test_root.rglob("*.py")):
            try:
                if check_id in path.read_text(encoding="utf-8"):
                    result.append(str(path.relative_to(_REPO_ROOT)))
            except OSError:
                continue
    return result


def build_inventory() -> dict[str, Any]:
    """Return rule metadata sorted by stable check ID."""
    rules = []
    for rule in get_all_rules():
        metadata = getattr(rule, "metadata", None)
        if metadata is None:
            raise ValueError(f"Registered rule {getattr(rule, '__name__', '<unknown>')} has no metadata.")
        attributes, source_file = _rule_source(rule)
        test_files = _test_references(metadata.check_id)
        rules.append({
            "check_id": metadata.check_id,
            "service": metadata.service,
            "resource_type": metadata.resource_type,
            "severity": metadata.severity.value,
            "category": metadata.category,
            "title": metadata.title,
            "description": metadata.description,
            "remediation": metadata.remediation,
            "rule_source_file": source_file,
            "observed_attribute_keys": sorted(attributes),
            "test_reference_files": test_files,
            "test_reference_count": len(test_files),
            "coverage_note": "Static attribute keys and test-file references are inventory aids, not proof of branch coverage.",
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
