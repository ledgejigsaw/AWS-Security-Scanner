"""Validate the upstream mapping ledger against the local rule registry."""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aws_security_scanner.rules.registry import get_all_rules  # noqa: E402

VALID = {"equivalent", "partial", "missing", "not-applicable", "not-reviewed"}


def main() -> int:
    data = json.loads((ROOT / "docs/upstream-rule-mapping.json").read_text(encoding="utf-8"))
    ids = {rule.metadata.check_id for rule in get_all_rules()}
    errors = []
    seen = set()
    for index, row in enumerate(data.get("mappings", [])):
        status = row.get("status")
        scanner_id = row.get("scanner_check_id")
        if status not in VALID:
            errors.append(f"mapping[{index}] has invalid status {status!r}")
        if scanner_id is not None and scanner_id not in ids:
            errors.append(f"mapping[{index}] references unknown scanner check {scanner_id!r}")
        key = (scanner_id, row.get("upstream_project"), row.get("upstream_check_id"))
        if key in seen:
            errors.append(f"duplicate mapping key {key!r}")
        seen.add(key)
        required = ("scanner_check_id", "upstream_project", "upstream_check_id", "upstream_url", "upstream_version", "rationale")
        if status == "equivalent" and not all(row.get(field) for field in required):
            errors.append(f"mapping[{index}] labels equivalence without full provenance")
    print(json.dumps({"schema_version": data.get("schema_version"), "registered_rule_count": len(ids),
                      "mapping_count": len(data.get("mappings", [])), "errors": errors}, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
