"""Run offline benchmarks for rule evaluation, graph generation and reports.

Example:
    python scripts/benchmark_scan.py --input tests/fixtures/terraform/realistic_s3.json --sizes 100 500 1000
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aws_security_scanner.performance import benchmark_resources, replicate_resources
from aws_security_scanner.providers.terraform import TerraformProvider


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("tests/fixtures/terraform/realistic_s3.json"),
        help="Local Terraform JSON template file (no Terraform execution is performed).",
    )
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=[100, 500, 1000],
        help="Synthetic resource counts to measure (default: 100 500 1000).",
    )
    parser.add_argument("--output", type=Path, help="Optional path for the JSON results.")
    args = parser.parse_args()

    if not args.sizes or any(size < 1 for size in args.sizes):
        parser.error("--sizes must contain positive integers.")
    templates = TerraformProvider(args.input).discover()
    if not templates:
        parser.error(f"No Terraform resources found in {args.input}.")

    results = {
        "benchmark_schema_version": "1.0.0",
        "input": str(args.input),
        "runs": [
            benchmark_resources(replicate_resources(templates, size))
            for size in args.sizes
        ],
    }
    rendered = json.dumps(results, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
