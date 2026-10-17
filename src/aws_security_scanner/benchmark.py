"""Evaluate scanner check IDs against explicit benchmark expectations."""
from __future__ import annotations

from collections import Counter
from typing import Any


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def evaluate_benchmark_case(case: dict[str, Any], observed_check_ids: list[str] | set[str]) -> dict[str, Any]:
    """Score one case using explicitly expected-positive and prohibited check IDs.

    IDs outside those declared sets are reported as unclassified, not silently
    treated as false positives. Check IDs listed as unresolved are excluded from
    scoring and surfaced separately.
    """
    fixture_id = case.get("fixture_id")
    if not isinstance(fixture_id, str) or not fixture_id:
        raise ValueError("benchmark case requires a non-empty fixture_id")
    expected = case.get("expected_findings", [])
    prohibited = case.get("prohibited_findings", [])
    unresolved = case.get("unresolved_check_ids", [])
    if not all(isinstance(value, list) and all(isinstance(item, str) and item for item in value) for value in (expected, prohibited, unresolved)):
        raise ValueError(f"benchmark case {fixture_id!r} contains invalid check ID lists")
    if set(expected) & set(prohibited):
        raise ValueError(f"benchmark case {fixture_id!r} lists a check as both expected and prohibited")
    observed = set(observed_check_ids)
    unresolved_set = set(unresolved)
    expected_set = set(expected) - unresolved_set
    prohibited_set = set(prohibited) - unresolved_set
    true_positive = expected_set & observed
    false_negative = expected_set - observed
    false_positive = prohibited_set & observed
    true_negative = prohibited_set - observed
    classified = expected_set | prohibited_set
    return {
        "fixture_id": fixture_id,
        "true_positive": sorted(true_positive),
        "false_negative": sorted(false_negative),
        "false_positive": sorted(false_positive),
        "true_negative": sorted(true_negative),
        "unresolved_check_ids": sorted(unresolved_set),
        "unclassified_observed_check_ids": sorted(observed - classified - unresolved_set),
        "counts": {"tp": len(true_positive), "fn": len(false_negative), "fp": len(false_positive), "tn": len(true_negative)},
    }


def evaluate_benchmark_suite(manifest: dict[str, Any], observed_by_fixture: dict[str, list[str] | set[str]]) -> dict[str, Any]:
    """Evaluate all cases and return deterministic aggregate metrics."""
    if manifest.get("schema_version") != "1.0":
        raise ValueError("unsupported benchmark manifest schema_version; expected '1.0'")
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("benchmark manifest cases must be a list")
    results = []
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each benchmark case must be an object")
        fixture_id = case.get("fixture_id")
        if not isinstance(fixture_id, str) or fixture_id in seen:
            raise ValueError("benchmark fixture_id values must be unique non-empty strings")
        seen.add(fixture_id)
        observed = observed_by_fixture.get(fixture_id, [])
        if not isinstance(observed, (list, set)) or not all(isinstance(item, str) for item in observed):
            raise ValueError(f"observed check IDs for {fixture_id!r} must be a list or set of strings")
        results.append(evaluate_benchmark_case(case, observed))
    totals = Counter()
    for result in results:
        totals.update(result["counts"])
    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision is not None and recall is not None and precision + recall else None
    return {
        "schema_version": "1.0",
        "case_count": len(results),
        "metrics": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": totals["tn"], "precision": precision, "recall": recall, "f1": f1},
        "cases": sorted(results, key=lambda item: item["fixture_id"]),
        "limitations": [
            "False positives are counted only for check IDs explicitly marked prohibited in the manifest.",
            "Unclassified observed checks are reported but not scored until the benchmark author labels them.",
            "Fixture metrics do not establish detection quality for every real AWS account or configuration.",
        ],
    }
