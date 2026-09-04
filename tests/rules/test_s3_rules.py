import json

from aws_security_scanner.models.finding import Severity
from aws_security_scanner.rules.s3_rules import check_public_bucket


def load_fixture(filename: str) -> dict:
    with open(f"tests/fixtures/s3/{filename}") as file:
        return json.load(file)


def test_public_bucket_is_critical():
    bucket = load_fixture("insecure_bucket.json")

    findings = check_public_bucket(bucket)

    assert len(findings) == 1
    assert findings[0].check_id == "S3-001"
    assert findings[0].severity == Severity.CRITICAL


def test_private_bucket_has_no_findings():
    bucket = load_fixture("secure_bucket.json")

    findings = check_public_bucket(bucket)

    assert findings == []