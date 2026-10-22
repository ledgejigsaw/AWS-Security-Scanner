"""Export a complete per-rule, per-upstream-tool mapping ledger.

Curated reviewed mappings are preserved; missing pairs are emitted as not-reviewed.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aws_security_scanner.rules.registry import get_all_rules  # noqa: E402

UPSTREAMS = {
    "Prowler": "https://github.com/prowler-cloud/prowler",
    "ScoutSuite": "https://github.com/nccgroup/ScoutSuite",
    "Checkov": "https://github.com/bridgecrewio/checkov",
}


def build_mapping() -> dict:
    curated_path = ROOT / "docs/upstream-rule-mapping.json"
    curated = json.loads(curated_path.read_text(encoding="utf-8"))
    curated_rows = [row for row in curated.get("mappings", []) if row.get("scanner_check_id")]
    by_key = {(row.get("scanner_check_id"), row.get("upstream_project")): row for row in curated_rows}
    rows = []
    for rule in sorted(get_all_rules(), key=lambda item: item.metadata.check_id):
        metadata = rule.metadata
        for upstream_name, upstream_url in UPSTREAMS.items():
            row = by_key.get((metadata.check_id, upstream_name))
            if row is None:
                row = {
                    "scanner_check_id": metadata.check_id,
                    "scanner_service": metadata.service,
                    "scanner_resource_type": metadata.resource_type,
                    "upstream_project": upstream_name,
                    "upstream_check_id": None,
                    "upstream_url": upstream_url,
                    "upstream_version": None,
                    "status": "not-reviewed",
                    "rationale": "No check-level semantic review has been recorded. Do not infer equivalence from a similar title or service.",
                    "evidence_required": ["scope and condition review", "secure/insecure cases", "unknown/error behaviour", "severity and remediation review"],
                }
            else:
                row = dict(row)
                row.setdefault("scanner_service", metadata.service)
                row.setdefault("scanner_resource_type", metadata.resource_type)
            rows.append(row)
    # Preserve explicitly recorded project-level/uncategorised notes after the rule matrix.
    rows.extend(row for row in curated.get("mappings", []) if not row.get("scanner_check_id"))
    rows.sort(key=lambda row: (str(row.get("scanner_check_id") or ""), str(row.get("upstream_project") or ""), str(row.get("upstream_check_id") or "")))
    return {
        "schema_version": "1.0.0",
        "purpose": "Complete rule-to-upstream-tool comparison matrix. Not-reviewed is the default; it is not a parity claim.",
        "updated_on": curated.get("updated_on"),
        "status_values": curated.get("status_values", []),
        "upstream_projects": curated.get("upstream_projects", []),
        "registered_rule_count": len(get_all_rules()),
        "mapping_count": len(rows),
        "mappings": rows,
        "prioritization": curated.get("prioritization", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write JSON to a file; defaults to stdout.")
    args = parser.parse_args()
    rendered = json.dumps(build_mapping(), indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
