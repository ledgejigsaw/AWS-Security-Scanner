import hashlib
import json
from pathlib import Path
from typing import Iterable

from aws_security_scanner.models.finding import Finding, Severity


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
BASELINE_VERSION = 1


def finding_fingerprint(finding: Finding) -> str:
    """Return a stable identity for a finding, excluding changing evidence text."""
    identity = {
        "check_id": finding.check_id,
        "service": finding.service,
        "resource": finding.resource,
        "region": finding.region,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def filter_by_minimum_severity(
    findings: Iterable[Finding],
    minimum: Severity | str | None = None,
) -> list[Finding]:
    """Keep findings at or above the selected severity threshold."""
    findings = list(findings)
    if minimum is None:
        return findings

    try:
        threshold = SEVERITY_ORDER[Severity(minimum)]
    except (ValueError, KeyError) as error:
        valid = ", ".join(severity.value for severity in Severity)
        raise ValueError(
            f"Invalid minimum severity {minimum!r}. Choose one of: {valid}."
        ) from error

    return [
        finding
        for finding in findings
        if SEVERITY_ORDER[finding.severity] >= threshold
    ]


def load_baseline(path: str | Path) -> set[str]:
    """Load and validate a versioned baseline of finding fingerprints."""
    baseline_path = Path(path)
    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Unable to read finding baseline '{baseline_path}': {error}"
        ) from error

    if not isinstance(payload, dict) or payload.get("version") != BASELINE_VERSION:
        raise ValueError(
            f"Unsupported finding baseline format in '{baseline_path}'. "
            f"Expected version {BASELINE_VERSION}."
        )

    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(value, str) and value for value in fingerprints
    ):
        raise ValueError(
            f"Invalid fingerprints in finding baseline '{baseline_path}'."
        )

    return set(fingerprints)


def write_baseline(
    findings: Iterable[Finding],
    path: str | Path,
) -> None:
    """Write a deterministic baseline containing the current finding identities."""
    fingerprints = sorted({finding_fingerprint(finding) for finding in findings})
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(
            {
                "version": BASELINE_VERSION,
                "fingerprints": fingerprints,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


def exclude_baselined_findings(
    findings: Iterable[Finding],
    baseline_fingerprints: set[str],
) -> list[Finding]:
    """Exclude findings whose stable identities already exist in a baseline."""
    return [
        finding
        for finding in findings
        if finding_fingerprint(finding) not in baseline_fingerprints
    ]
