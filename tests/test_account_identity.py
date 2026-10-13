import hashlib
import json

from aws_security_scanner.baseline_history import (
    finding_fingerprint,
    load_baseline_records,
    write_baseline,
)
from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.s3_rules import check_public_bucket


def make_finding(account_id=None):
    return Finding(
        check_id="S3-001",
        severity=Severity.CRITICAL,
        service="S3",
        resource="shared-name",
        title="Public bucket",
        description="Bucket is public",
        remediation="Restrict access",
        region="eu-west-2",
        evidence="public=true",
        account_id=account_id,
    )


def test_engine_propagates_resource_account_id_to_findings():
    resource = Resource(
        resource_type="aws_s3_bucket",
        resource_id="public-bucket",
        attributes={"public": True},
        source="aws",
        region="eu-west-2",
        account_id="111111111111",
    )

    findings = RuleEngine([check_public_bucket]).scan([resource])

    assert len(findings) == 1
    assert findings[0].account_id == "111111111111"


def test_legacy_fingerprint_is_unchanged_without_account_id():
    finding = make_finding()
    legacy_identity = {
        "check_id": "S3-001",
        "service": "S3",
        "resource": "shared-name",
        "region": "eu-west-2",
    }
    expected = hashlib.sha256(
        json.dumps(legacy_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    assert finding_fingerprint(finding) == expected


def test_account_id_separates_same_resource_findings_across_accounts():
    first = make_finding("111111111111")
    second = make_finding("222222222222")

    assert finding_fingerprint(first) != finding_fingerprint(second)


def test_baseline_persists_account_id_when_available(tmp_path):
    finding = make_finding("111111111111")
    path = tmp_path / "baseline.json"

    write_baseline([finding], path)
    records = load_baseline_records(path)
    record = next(iter(records.values()))

    assert record["account_id"] == "111111111111"
