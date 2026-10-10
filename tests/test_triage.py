import json

import pytest

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.triage import (
    exclude_baselined_findings,
    filter_by_minimum_severity,
    finding_fingerprint,
    load_baseline,
    write_baseline,
)


def make_finding(
    severity: Severity,
    resource: str = "company-data",
    evidence: str | None = None,
) -> Finding:
    return Finding(
        check_id="S3-001",
        severity=severity,
        service="S3",
        resource=resource,
        title="Public bucket",
        description="Bucket may be publicly accessible.",
        remediation="Restrict public access.",
        region="eu-west-2",
        evidence=evidence,
    )


def test_minimum_severity_keeps_threshold_and_higher_findings():
    findings = [
        make_finding(Severity.INFO, "info"),
        make_finding(Severity.LOW, "low"),
        make_finding(Severity.MEDIUM, "medium"),
        make_finding(Severity.HIGH, "high"),
        make_finding(Severity.CRITICAL, "critical"),
    ]

    result = filter_by_minimum_severity(findings, "HIGH")

    assert [finding.resource for finding in result] == ["high", "critical"]


def test_minimum_severity_defaults_to_all_findings():
    findings = [make_finding(Severity.INFO), make_finding(Severity.CRITICAL)]

    assert filter_by_minimum_severity(findings) == findings


def test_minimum_severity_rejects_unknown_value():
    with pytest.raises(ValueError, match="Invalid minimum severity"):
        filter_by_minimum_severity([], "URGENT")


def test_finding_fingerprint_ignores_evidence_but_changes_for_resource():
    first = make_finding(Severity.HIGH, evidence="before")
    updated_evidence = make_finding(Severity.HIGH, evidence="after")
    different_resource = make_finding(Severity.HIGH, resource="another-bucket")

    assert finding_fingerprint(first) == finding_fingerprint(updated_evidence)
    assert finding_fingerprint(first) != finding_fingerprint(different_resource)


def test_baseline_round_trip_and_excludes_existing_findings(tmp_path):
    findings = [
        make_finding(Severity.HIGH, "existing", evidence="evidence-v1"),
        make_finding(Severity.CRITICAL, "new"),
    ]
    path = tmp_path / "nested" / "baseline.json"

    write_baseline(findings[:1], path)
    fingerprints = load_baseline(path)

    remaining = exclude_baselined_findings(findings, fingerprints)

    assert len(remaining) == 1
    assert remaining[0].resource == "new"
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_load_baseline_rejects_unsupported_schema(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"version": 2, "fingerprints": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported finding baseline"):
        load_baseline(path)


def test_load_baseline_rejects_invalid_fingerprints(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"version": 1, "fingerprints": [42]}', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid fingerprints"):
        load_baseline(path)


def test_load_baseline_reports_missing_file(tmp_path):
    with pytest.raises(ValueError, match="Unable to read finding baseline"):
        load_baseline(tmp_path / "missing.json")
