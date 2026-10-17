#!/usr/bin/env python3
"""Evaluate scanner outputs against a versioned benchmark manifest.

Observed JSON format:
{
  "s3-public-bucket": ["S3-001"],
  "s3-encrypted-private-bucket": []
}
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aws_security_scanner.benchmark import evaluate_benchmark_suite


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="Versioned benchmark manifest JSON")
    parser.add_argument("--observed", required=True, type=Path, help="JSON mapping fixture IDs to observed check IDs")
    parser.add_argument("--output", type=Path, help="Optional output path (defaults to stdout)")
    args = parser.parse_args()

    manifest: Any = json.loads(args.manifest.read_text(encoding="utf-8"))
    observed: Any = json.loads(args.observed.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(observed, dict):
        parser.error("manifest and observed inputs must each contain a JSON object")
    result = evaluate_benchmark_suite(manifest, observed)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
