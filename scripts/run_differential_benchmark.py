"""Run deterministic offline differential benchmark cases.

The harness validates this scanner against versioned expected outcomes. It does
not install or invoke Prowler/Checkov and never claims parity for unmapped checks.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aws_security_scanner.cli import run_scan  # noqa: E402

VALID_STATUSES = {"equivalent", "partial", "not-equivalent", "not-applicable", "not-reviewed"}


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != "1.0.0":
        raise ValueError("Benchmark manifest must be an object with schema_version 1.0.0.")
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError("Benchmark manifest must contain a cases array.")
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"]:
            raise ValueError("Every benchmark case needs a non-empty id.")
        if case["id"] in seen:
            raise ValueError(f"Duplicate benchmark case id: {case['id']}")
        seen.add(case["id"])
        upstream = case.get("upstream", {})
        if not isinstance(upstream, dict) or upstream.get("status") not in VALID_STATUSES:
            raise ValueError(f"Case {case['id']} has an invalid upstream mapping status.")
        if upstream.get("status") == "equivalent" and not (
            upstream.get("tool") and upstream.get("check_id") and upstream.get("version") and upstream.get("rationale")
        ):
            raise ValueError(f"Equivalent case {case['id']} needs tool, check_id, version and rationale.")
    return data


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    input_path = (ROOT / str(case.get("input", ""))).resolve()
    try:
        input_path.relative_to(ROOT)
    except ValueError:
        return {"id": case["id"], "status": "error", "error": "input path escapes repository root"}
    if not input_path.is_file():
        return {"id": case["id"], "status": "error", "error": f"input file not found: {case.get('input')}"}
    try:
        findings = run_scan(source=case["source"], source_path=input_path)
    except Exception as error:
        return {"id": case["id"], "status": "error", "error": f"{type(error).__name__}: {error}"}
    actual = sorted({finding.check_id for finding in findings})
    expected = sorted(set(case.get("expected_check_ids", [])))
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    passed = not missing and not unexpected
    return {
        "id": case["id"], "status": "passed" if passed else "failed",
        "source": case["source"], "input": case["input"],
        "expected_check_ids": expected, "actual_check_ids": actual,
        "missing_check_ids": missing, "unexpected_check_ids": unexpected,
        "upstream_mapping_status": case["upstream"]["status"],
        "upstream_parity_claimed": case["upstream"]["status"] == "equivalent",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks/differential/manifest.json")
    parser.add_argument("--output", type=Path, help="Optional JSON report path; defaults to stdout.")
    args = parser.parse_args()
    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    results = [run_case(case) for case in manifest["cases"] if case["upstream"]["status"] != "not-reviewed" or case.get("expected_check_ids")]
    report = {
        "schema_version": manifest["schema_version"],
        "benchmark_kind": manifest.get("benchmark_kind"),
        "manifest": str(manifest_path.relative_to(ROOT)) if manifest_path.is_relative_to(ROOT) else str(manifest_path),
        "case_count": len(results),
        "passed": sum(item["status"] == "passed" for item in results),
        "failed": sum(item["status"] == "failed" for item in results),
        "errors": sum(item["status"] == "error" for item in results),
        "upstream_equivalent_cases": sum(item.get("upstream_parity_claimed") is True for item in results),
        "results": results,
        "limitations": [
            "A passing local expected-outcome case does not establish equivalence with an upstream tool.",
            "Prowler and Checkov are not invoked; upstream versions/check IDs must be manually reviewed and pinned before an equivalent status is accepted.",
            "This sample does not establish full scanner coverage, false-negative rate, or live-AWS correctness.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if report["failed"] == 0 and report["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
