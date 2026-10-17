"""Offline, reproducible performance probes for core scan stages.

These helpers deliberately accept already-normalised resources: they never create
AWS clients, read credentials, or make network requests.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from time import perf_counter
from typing import Any

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.graph import build_resource_graph
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report
from aws_security_scanner.rules.registry import get_all_rules


def replicate_resources(templates: list[Resource], count: int) -> list[Resource]:
    """Create an isolated synthetic dataset by copying normalised templates."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative integer.")
    if count and not templates:
        raise ValueError("at least one template resource is required when count is non-zero.")

    resources: list[Resource] = []
    for index in range(count):
        template = templates[index % len(templates)]
        resources.append(
            replace(
                template,
                resource_id=f"{template.resource_id}-benchmark-{index:06d}",
                attributes=deepcopy(template.attributes),
                relationships=deepcopy(template.relationships),
            )
        )
    return resources


def _measure(operation):
    started = perf_counter()
    result = operation()
    return result, perf_counter() - started


def benchmark_resources(resources: list[Resource]) -> dict[str, Any]:
    """Measure rule evaluation, graph generation and report serialisation."""
    engine = RuleEngine(get_all_rules())
    findings, rule_seconds = _measure(lambda: engine.scan(resources))
    graph, graph_seconds = _measure(lambda: build_resource_graph(resources, findings))
    json_report, json_seconds = _measure(lambda: build_json_report(findings))
    sarif_report, sarif_seconds = _measure(lambda: build_sarif_report(findings))

    import json

    return {
        "schema_version": "1.0.0",
        "resource_count": len(resources),
        "finding_count": len(findings),
        "stages": {
            "rule_evaluation": {"seconds": round(rule_seconds, 6)},
            "resource_graph": {
                "seconds": round(graph_seconds, 6),
                "nodes": len(graph.get("nodes", [])),
                "edges": len(graph.get("edges", [])),
                "unresolved_relationships": len(graph.get("unresolved_relationships", [])),
            },
            "json_report": {
                "seconds": round(json_seconds, 6),
                "bytes": len(json.dumps(json_report, separators=(",", ":")).encode("utf-8")),
            },
            "sarif_report": {
                "seconds": round(sarif_seconds, 6),
                "bytes": len(json.dumps(sarif_report, separators=(",", ":")).encode("utf-8")),
            },
        },
        "notes": [
            "Timings are environment-specific observations, not CI pass/fail thresholds.",
            "The benchmark uses synthetic copies of local input resources; it does not measure AWS API latency.",
            "No credentials, cloud APIs, Terraform execution, or external services are used.",
        ],
    }
