import json
from datetime import date

import pytest

from aws_security_scanner.baseline_history import (
    active_baseline_fingerprints,
    diff_findings,
    finding_fingerprint,
    load_baseline_records,
    write_baseline,
)
from aws_security_scanner.models.finding import Finding, Severity


def finding(resource="bucket-a", evidence="evidence-1", severity=Severity.HIGH):
    return Finding(check_id="S3-001", severity=severity, service="S3", resource=resource,
                   title="Public bucket", description="Public access", remediation="Restrict access",
                   region="eu-west-2", evidence=evidence)


def test_diff_is_deterministic_and_evidence_does_not_change_identity():
    previous = finding("old")
    current = [finding("old", "evidence changed"), finding("new")]
    baseline = {finding_fingerprint(previous): {"fingerprint": finding_fingerprint(previous),
                "check_id": "S3-001", "service": "S3", "resource": "old",
                "region": "eu-west-2", "severity": "HIGH", "title": "Public bucket"}}
    result = diff_findings(current, baseline)
    assert len(result["new"]) == 1 and result["new"][0]["resource"] == "new"
    assert result["resolved"] == []
    assert len(result["unchanged"]) == 1 and result["unchanged"][0]["resource"] == "old"


def test_v2_round_trip_and_expired_suppression_is_inactive(tmp_path):
    item = finding()
    fingerprint = finding_fingerprint(item)
    path = tmp_path / "baseline.json"
    write_baseline([item], path, {fingerprint: {"reason": "Accepted risk", "owner": "platform", "expires_on": "2026-01-01"}})
    records = load_baseline_records(path)
    assert active_baseline_fingerprints(records, as_of=date(2026, 2, 1)) == set()
    assert active_baseline_fingerprints(records, as_of=date(2025, 12, 1)) == {fingerprint}


def test_legacy_v1_baseline_remains_supported(tmp_path):
    item = finding()
    fingerprint = finding_fingerprint(item)
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"version": 1, "fingerprints": [fingerprint]}), encoding="utf-8")
    records = load_baseline_records(path)
    assert set(records) == {fingerprint}
    assert active_baseline_fingerprints(records) == {fingerprint}


@pytest.mark.parametrize("expiry", ["yesterday", "2026-99-99", ""])
def test_invalid_suppression_expiry_is_rejected(tmp_path, expiry):
    item = finding()
    fingerprint = finding_fingerprint(item)
    path = tmp_path / "baseline.json"
    write_baseline([item], path)
    payload = json.loads(path.read_text())
    payload["findings"][0]["suppression"] = {"reason": "accepted", "expires_on": expiry}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline_records(path)


def test_suppression_requires_reason(tmp_path):
    item = finding()
    fingerprint = finding_fingerprint(item)
    path = tmp_path / "baseline.json"
    write_baseline([item], path)
    payload = json.loads(path.read_text())
    payload["findings"][0]["suppression"] = {"owner": "team"}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="reason is required"):
        load_baseline_records(path)


def test_malformed_and_unknown_version_baselines_are_rejected(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text('{"version": 3, "findings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported"):
        load_baseline_records(path)
    path.write_text('{"version": 2, "findings": "not-a-list"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid findings"):
        load_baseline_records(path)
