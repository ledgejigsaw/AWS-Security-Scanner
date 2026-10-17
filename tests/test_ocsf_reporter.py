from datetime import datetime, timezone

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.ocsf_reporter import build_ocsf_report, write_ocsf_report


def finding(severity=Severity.HIGH, **kwargs):
    values = dict(
        check_id="S3-001",
        severity=severity,
        service="S3",
        resource="example-bucket",
        title="S3 bucket is publicly accessible",
        description="The bucket is publicly accessible.",
        remediation="Restrict public access.",
        region="eu-west-2",
        evidence="public=true",
        account_id="111111111111",
    )
    values.update(kwargs)
    return Finding(**values)


def test_ocsf_export_uses_detection_finding_class_and_maps_severity():
    generated = datetime(2026, 10, 17, 8, 0, tzinfo=timezone.utc)
    events = build_ocsf_report(
        [finding(Severity.CRITICAL), finding(Severity.INFO, check_id="IAC-HCL-001")],
        generated_at=generated,
    )

    assert len(events) == 2
    event = events[0]
    assert event["class_uid"] == 2004
    assert event["class_name"] == "Detection Finding"
    assert event["category_uid"] == 2
    assert event["activity_id"] == 1
    assert event["type_uid"] == 200401
    assert event["severity_id"] == 5
    assert event["severity"] == "Critical"
    assert event["metadata"]["version"] == "1.7.0"
    assert event["cloud"] == {
        "provider": "AWS",
        "region": "eu-west-2",
        "account": {"uid": "111111111111"},
    }
    assert event["resources"][0]["uid"] == "example-bucket"
    assert event["finding_info"]["analytic"]["uid"] == "S3-001"
    assert event["unmapped"]["evidence"] == "public=true"
    assert events[1]["severity_id"] == 1


def test_ocsf_finding_uid_is_stable_and_changes_with_source_identity():
    first = finding(source_type="inspector", source_id="finding-1", source_product="Inspector")
    same = finding(source_type="inspector", source_id="finding-1", source_product="Inspector")
    different = finding(source_type="inspector", source_id="finding-2", source_product="Inspector")

    a, b, c = build_ocsf_report([first, same, different], generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert a["finding_info"]["uid"] == b["finding_info"]["uid"]
    assert a["finding_info"]["uid"] != c["finding_info"]["uid"]


def test_ocsf_export_writes_json_array(tmp_path):
    output = tmp_path / "reports" / "scan.ocsf.json"
    write_ocsf_report([finding()], output)

    import json
    events = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(events, list)
    assert events[0]["class_name"] == "Detection Finding"
