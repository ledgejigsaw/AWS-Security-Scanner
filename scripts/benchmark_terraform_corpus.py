"""Run the checked-in offline Terraform HCL benchmark corpus."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from aws_security_scanner.cli import run_scan  # noqa: E402
from aws_security_scanner.scan_summary import build_scan_summary  # noqa: E402


def _validate_manifest(manifest: Any, repo_root: Path) -> list[dict[str, Any]]:
    """Validate benchmark cases before running scans or resolving paths."""
    if not isinstance(manifest, dict):
        raise ValueError("Terraform benchmark manifest must be a JSON object.")
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("Unsupported Terraform benchmark manifest schema.")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Terraform benchmark manifest must contain a non-empty cases list.")

    root = repo_root.resolve()
    seen_ids: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"Benchmark case at index {index} must be an object.")
        case_id = case.get("id")
        path_value = case.get("path")
        expected_ids = case.get("expected_check_ids")
        expected_status = case.get("expected_status")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError(f"Benchmark case at index {index} has no non-empty id.")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate Terraform benchmark case id: {case_id}")
        seen_ids.add(case_id)
        if not isinstance(path_value, str) or not path_value.strip():
            raise ValueError(f"Benchmark case '{case_id}' has no non-empty path.")
        if (
            not isinstance(expected_ids, list)
            or any(not isinstance(check_id, str) or not check_id.strip() for check_id in expected_ids)
        ):
            raise ValueError(f"Benchmark case '{case_id}' expected_check_ids must be a list of non-empty strings.")
        if len(expected_ids) != len(set(expected_ids)):
            raise ValueError(f"Benchmark case '{case_id}' contains duplicate expected check IDs.")
        if not isinstance(expected_status, str) or expected_status not in {"complete", "incomplete"}:
            raise ValueError(f"Benchmark case '{case_id}' expected_status must be 'complete' or 'incomplete'.")
        case_path = (root / path_value).resolve()
        if not case_path.is_relative_to(root):
            raise ValueError(f"Benchmark case path escapes repository root: {path_value}")
        if not case_path.exists():
            raise ValueError(f"Benchmark case '{case_id}' path does not exist: {path_value}")
        case_class = case.get("class", "unspecified")
        if not isinstance(case_class, str) or case_class not in {"secure", "insecure", "unknown", "unspecified"}:
            raise ValueError(f"Benchmark case '{case_id}' has unsupported class: {case_class}")
        if "notes" in case and not isinstance(case["notes"], str):
            raise ValueError(f"Benchmark case '{case_id}' notes must be a string.")
        validated.append(case)
    return validated


def run_benchmark(manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Run all manifest cases and return a deterministic comparison document."""
    manifest_file = Path(manifest_path) if manifest_path else (
        _REPO_ROOT / "tests" / "fixtures" / "terraform-hcl-benchmark" / "manifest.json"
    )
    if not manifest_file.is_file():
        raise ValueError(f"Benchmark manifest does not exist: {manifest_file}")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    cases = _validate_manifest(manifest, _REPO_ROOT)

    results = []
    for case in cases:
        case_path = (_REPO_ROOT / case["path"]).resolve()
        if not case_path.is_relative_to(_REPO_ROOT.resolve()):
            raise ValueError(f"Benchmark case path escapes repository root: {case['path']}")
        started = perf_counter()
        findings = run_scan("hcl", case_path)
        duration = perf_counter() - started
        observed_ids = sorted({finding.check_id for finding in findings})
        summary = build_scan_summary(
            findings,
            source="hcl",
            region=None,
            services=None,
            report_format="json",
            report_path=str(case_path),
            duration_seconds=duration,
        )
        expected_ids = sorted(set(case.get("expected_check_ids", [])))
        expected_status = case.get("expected_status")
        passed = observed_ids == expected_ids and summary["status"] == expected_status
        results.append({
            "id": case["id"],
            "class": case.get("class", "unspecified"),
            "passed": passed,
            "expected_check_ids": expected_ids,
            "observed_check_ids": observed_ids,
            "expected_status": expected_status,
            "observed_status": summary["status"],
            "duration_seconds": round(duration, 6),
            "notes": case.get("notes", ""),
        })

    return {
        "schema_version": "1.0.0",
        "benchmark": "terraform-hcl-offline",
        "manifest": str(manifest_file.relative_to(_REPO_ROOT.resolve()))
        if manifest_file.resolve().is_relative_to(_REPO_ROOT.resolve())
        else str(manifest_file),
        "case_count": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="Optional alternate benchmark manifest.")
    parser.add_argument("--output", type=Path, help="Write result JSON to this path; defaults to stdout.")
    args = parser.parse_args()
    try:
        result = run_benchmark(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
