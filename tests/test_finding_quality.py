from aws_security_scanner.finding_quality import validate_finding_quality
from aws_security_scanner.models.finding import Finding, Severity


def finding(**overrides):
    values = dict(check_id="S3-001", severity=Severity.HIGH, service="S3", resource="example-bucket", title="Public bucket", description="Public access detected", remediation="Restrict public access", evidence="BlockPublicPolicy=false")
    values.update(overrides)
    return Finding(**values)


def test_valid_finding_has_no_quality_diagnostics():
    result = validate_finding_quality([finding()])
    assert result["findings_checked"] == 1
    assert result["diagnostics"] == []


def test_missing_evidence_resource_and_remediation_are_reported():
    result = validate_finding_quality([finding(resource="", evidence=None, remediation=" ")])
    codes = {item["code"] for item in result["diagnostics"]}
    assert {"missing_resource_scope", "missing_evidence", "missing_remediation"} <= codes


def test_placeholder_evidence_is_not_accepted_as_observation():
    result = validate_finding_quality([finding(evidence="unknown")])
    assert "placeholder_evidence" in {item["code"] for item in result["diagnostics"]}


def test_credential_like_evidence_is_flagged_without_echoing_secret():
    secret = "AKIA1234567890ABCDEF"
    result = validate_finding_quality([finding(evidence=f"Observed key {secret}")])
    assert "evidence_may_contain_secret" in {item["code"] for item in result["diagnostics"]}
    assert secret not in str(result)


def test_quality_report_is_deterministic_and_does_not_mutate_findings():
    item = finding(evidence="TBD")
    before = item.evidence
    first = validate_finding_quality([item])
    second = validate_finding_quality([item])
    assert first == second
    assert item.evidence == before
