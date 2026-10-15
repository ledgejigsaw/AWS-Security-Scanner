import json

import pytest

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.risk import (
    RiskScoringConfigError,
    load_risk_config,
    score_findings,
)
from aws_security_scanner.reporting.html_reporter import build_html_report
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report


def finding(check_id="S3-001", severity=Severity.CRITICAL, resource="bucket-a"):
    return Finding(
        check_id=check_id,
        severity=severity,
        service="S3",
        resource=resource,
        title="Example finding",
        description="Example description",
        remediation="Review configuration",
        evidence="public=true",
    )


def test_default_scores_are_deterministic_and_severity_remains_unchanged():
    items = [
        finding(severity=Severity.CRITICAL),
        finding(check_id="S3-002", severity=Severity.HIGH),
        finding(check_id="S3-003", severity=Severity.MEDIUM),
        finding(check_id="S3-004", severity=Severity.LOW),
        finding(check_id="S3-005", severity=Severity.INFO),
    ]

    scored = score_findings(items)

    assert [item.risk_score for item in scored] == [90, 70, 45, 25, 10]
    assert [item.severity for item in scored] == [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    ]
    assert all(item.risk_score_version == "1" for item in scored)
    assert all(item.risk_explanation["model_version"] == "1" for item in scored)


def test_configured_exposure_criticality_and_confidence_are_explained(tmp_path):
    path = tmp_path / "risk.json"
    path.write_text(json.dumps({
        "version": 1,
        "check_overrides": {"S3-001": {"exposure_bonus": 10, "confidence": 0.8}},
        "resource_criticality": {"bucket-a": 10},
    }), encoding="utf-8")
    config = load_risk_config(path, {"S3-001"})

    [scored] = score_findings([finding()], config)

    assert scored.risk_score == 88  # round((90 + 10 + 10) * 0.8)
    assert scored.risk_explanation["severity_base"] == 90
    assert scored.risk_explanation["exposure_bonus"] == 10
    assert scored.risk_explanation["resource_criticality_bonus"] == 10
    assert scored.risk_explanation["detection_confidence"] == 0.8


def test_missing_resource_criticality_is_neutral(tmp_path):
    path = tmp_path / "risk.json"
    path.write_text(json.dumps({"version": 1}), encoding="utf-8")

    [scored] = score_findings([finding()], load_risk_config(path, {"S3-001"}))

    assert scored.risk_score == 90
    assert scored.risk_explanation["resource_criticality_bonus"] == 0


def test_score_is_capped_at_100():
    config_path = None
    from aws_security_scanner.risk import RiskScoringConfig, CheckRiskOverride

    config = RiskScoringConfig(
        check_overrides={"S3-001": CheckRiskOverride(exposure_bonus=10, confidence=1.0)},
        resource_criticality={"bucket-a": 10},
    )
    [scored] = score_findings([finding()], config)
    assert scored.risk_score == 100


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"version": 2}, "version: 1"),
        ({"version": 1, "check_overrides": {"UNKNOWN-001": {}}}, "Unknown check ID"),
        ({"version": 1, "check_overrides": {"S3-001": {"exposure_bonus": 11}}}, "0 to 10"),
        ({"version": 1, "check_overrides": {"S3-001": {"confidence": True}}}, "0 to 1"),
        ({"version": 1, "resource_criticality": {"bucket-a": -1}}, "0 to 10"),
        ({"version": 1, "unexpected": True}, "Unsupported risk configuration"),
    ],
)
def test_invalid_risk_configuration_is_rejected(tmp_path, payload, message):
    path = tmp_path / "risk.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RiskScoringConfigError, match=message):
        load_risk_config(path, {"S3-001"})


def test_invalid_json_risk_configuration_is_rejected(tmp_path):
    path = tmp_path / "risk.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(RiskScoringConfigError, match="not valid JSON"):
        load_risk_config(path, {"S3-001"})


def test_risk_metadata_is_opt_in_and_reported_in_json_html_and_sarif():
    plain = finding()
    assert "risk_score" not in build_json_report([plain])["findings"][0]
    assert "Risk score (v1)" not in build_html_report([plain])
    assert "riskScore" not in build_sarif_report([plain])["runs"][0]["results"][0]["properties"]

    [scored] = score_findings([finding()])
    json_result = build_json_report([scored])["findings"][0]
    assert json_result["risk_score"] == 90
    assert json_result["risk_score_version"] == "1"
    assert json_result["risk_explanation"]["severity_base"] == 90

    html = build_html_report([scored])
    assert "Risk score (v1)" in html
    assert "90" in html
    assert "severity_base" in html

    sarif = build_sarif_report([scored])["runs"][0]["results"][0]["properties"]
    assert sarif["riskScore"] == 90
    assert sarif["riskScoreVersion"] == "1"
    assert sarif["riskExplanation"]["severity_base"] == 90
