"""Non-mutating quality checks for security finding records.

Diagnostics intentionally omit raw evidence and resource identifiers to avoid
re-emitting potentially sensitive data into quality reports.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable

_PLACEHOLDERS = {"", "todo", "tbd", "unknown", "n/a", "na", "none", "null", "placeholder", "not available"}
_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(password|client_secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def validate_finding_quality(findings: Iterable[Any]) -> dict[str, Any]:
    """Validate required finding context and evidence without changing records."""
    diagnostics: list[dict[str, str]] = []
    count = 0
    for finding in findings:
        count += 1
        check_id = _text(getattr(finding, "check_id", None)) or "<missing-check-id>"
        resource = _text(getattr(finding, "resource", None))
        evidence = _text(getattr(finding, "evidence", None))
        remediation = _text(getattr(finding, "remediation", None))

        def add(code: str, message: str, severity: str = "warning") -> None:
            diagnostics.append({"check_id": check_id, "code": code, "severity": severity, "message": message})

        if check_id == "<missing-check-id>":
            add("missing_check_id", "Finding has no non-empty check identifier", "error")
        if not resource:
            add("missing_resource_scope", "Finding has no non-empty resource scope", "error")
        if not remediation:
            add("missing_remediation", "Finding has no remediation guidance")
        if not evidence:
            add("missing_evidence", "Finding has no evidence recorded")
        elif evidence.casefold() in _PLACEHOLDERS:
            add("placeholder_evidence", "Finding evidence is a placeholder rather than an observation")
        if evidence and any(pattern.search(evidence) for pattern in _SECRET_PATTERNS):
            add("evidence_may_contain_secret", "Evidence resembles a credential or private key; review and redact at source", "error")
    diagnostics.sort(key=lambda item: (item["check_id"], item["code"], item["message"]))
    counts = Counter(item["code"] for item in diagnostics)
    return {
        "schema_version": "1.0",
        "findings_checked": count,
        "diagnostic_count": len(diagnostics),
        "diagnostics_by_code": dict(sorted(counts.items())),
        "diagnostics": diagnostics,
        "limitations": [
            "Quality diagnostics do not prove a security finding is false or true.",
            "Evidence contents and resource identifiers are intentionally omitted from this report.",
            "Secret detection uses conservative patterns and cannot identify every sensitive value.",
        ],
    }
