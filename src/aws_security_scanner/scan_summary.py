"""Versioned machine-readable CLI summary and finding-threshold helpers."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from aws_security_scanner.models.finding import Finding, Severity


SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


def threshold_is_met(findings: list[Finding], fail_on: str | None) -> bool:
    """Return whether any finding meets or exceeds the requested severity."""
    if fail_on is None:
        return False
    if fail_on not in SEVERITY_RANK:
        raise ValueError(f"Unsupported failure threshold: {fail_on!r}")
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity.value] <= threshold for finding in findings)


def scan_exit_code(*, incomplete: bool, threshold_met: bool) -> int:
    """Return the documented process exit code for a completed scan attempt."""
    if incomplete:
        return 1
    if threshold_met:
        return 3
    return 0


def build_scan_summary(
    findings: list[Finding],
    *,
    source: str,
    region: str | None,
    services: list[str] | None,
    report_format: str,
    report_path: str | Path,
    duration_seconds: float,
    discovery_coverage: list[dict[str, Any]] | None = None,
    assessment_metadata: dict[str, Any] | None = None,
    fail_on: str | None = None,
    threshold_met: bool = False,
) -> dict[str, Any]:
    """Build a stable summary without copying raw resource attributes or credentials."""
    counts = Counter(finding.severity.value for finding in findings)
    by_severity = {severity.value: counts[severity.value] for severity in Severity}
    coverage = discovery_coverage or []
    coverage_statuses = Counter(str(item.get("status", "unknown")) for item in coverage)
    coverage_gaps = sum(item.get("status") in {"partial", "failed"} for item in coverage)

    account_summary = None
    failed_accounts = 0
    if assessment_metadata is not None:
        raw_summary = assessment_metadata.get("summary", {})
        if isinstance(raw_summary, dict):
            failed_accounts = int(raw_summary.get("failed_accounts", 0) or 0)
            account_summary = {
                "total": int(raw_summary.get("total_accounts", 0) or 0),
                "successful": int(raw_summary.get("successful_accounts", 0) or 0),
                "failed": failed_accounts,
            }

    hcl_diagnostics = [
        finding for finding in findings
        if finding.check_id in {"IAC-HCL-001", "IAC-HCL-002", "IAC-HCL-003"}
    ] if source == "hcl" else []
    hcl_codes = Counter(finding.check_id for finding in hcl_diagnostics)
    hcl_analysis = {
        "status": "incomplete" if hcl_diagnostics else "complete",
        "diagnostics_total": len(hcl_diagnostics),
        "diagnostics_by_code": dict(sorted(hcl_codes.items())),
        "unresolved_expressions": hcl_codes.get("IAC-HCL-001", 0),
        "unexpanded_modules": hcl_codes.get("IAC-HCL-002", 0),
        "unevaluated_data_sources": hcl_codes.get("IAC-HCL-003", 0),
    }
    complete = coverage_gaps == 0 and failed_accounts == 0 and not hcl_diagnostics
    return {
        "schema_version": "1.0.0",
        "status": "complete" if complete else "incomplete",
        "scope": {
            "source": source,
            "region": region,
            "services": sorted(set(services)) if services else None,
        },
        "report": {
            "format": report_format,
            "path": str(report_path),
        },
        "duration_seconds": round(max(0.0, float(duration_seconds)), 6),
        "findings": {
            "total": len(findings),
            "by_severity": by_severity,
        },
        "discovery": {
            "domains_assessed": len(coverage),
            "domains_with_gaps": coverage_gaps,
            "statuses": dict(sorted(coverage_statuses.items())),
        },
        "analysis": hcl_analysis,
        "accounts": account_summary,
        "failure_threshold": {
            "severity": fail_on,
            "met": bool(threshold_met),
        },
    }


def write_scan_summary(summary: dict[str, Any], output_path: str | Path) -> None:
    """Write a standalone summary JSON document."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
