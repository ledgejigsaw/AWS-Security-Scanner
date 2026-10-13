from pathlib import Path

from aws_security_scanner.cli import build_parser
from aws_security_scanner.compliance import load_mapping_file
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.reporting.html_reporter import build_html_report
from aws_security_scanner.reporting.json_reporter import build_json_report
from aws_security_scanner.reporting.sarif_reporter import build_sarif_report
from aws_security_scanner.rules.registry import get_all_rules


def mapping_document():
    return {
        "schema_version": 1,
        "framework": {"name": "Example Framework", "version": "2026"},
        "mapping_notice": "Illustrative mapping; not a compliance determination.",
        "controls": [
            {
                "control_id": "AC-6",
                "title": "Least Privilege",
                "check_ids": ["IAM-001", "S3-006"],
                "confidence": "partial",
                "rationale": "The check provides evidence relevant to this objective.",
            }
        ],
    }


def finding(check_id="IAM-001"):
    return Finding(
        check_id=check_id,
        severity=Severity.HIGH,
        service="IAM",
        resource="example-resource",
        title="Example finding",
        description="Example description",
        remediation="Example remediation",
        region="eu-west-2",
        evidence="Example evidence",
    )


def test_bundled_mapping_references_registered_check_ids():
    registered_ids = {rule.metadata.check_id for rule in get_all_rules()}
    path = Path(__file__).parents[1] / "mappings" / "nist-sp-800-53-rev5.json"

    document = load_mapping_file(path, registered_ids)

    assert document["framework"]["version"] == "Rev. 5"


def test_json_report_includes_framework_and_mapping_rationale():
    report = build_json_report([finding()], mapping_document())

    assert report["compliance_framework"]["name"] == "Example Framework"
    assert report["compliance_framework"]["version"] == "2026"
    mapping = report["findings"][0]["compliance_mappings"][0]
    assert mapping["control_id"] == "AC-6"
    assert mapping["confidence"] == "partial"
    assert "relevant to this objective" in mapping["rationale"]


def test_json_report_without_mapping_keeps_existing_shape():
    report = build_json_report([finding()])

    assert "compliance_framework" not in report
    assert "compliance_mappings" not in report["findings"][0]


def test_html_report_includes_escaped_framework_mapping():
    document = mapping_document()
    document["framework"]["name"] = "Example <Framework>"
    report = build_html_report([finding("S3-006")], document)

    assert "Example &lt;Framework&gt;" in report
    assert "AC-6" in report
    assert "partial" in report
    assert "relevant to this objective" in report


def test_sarif_report_includes_framework_and_mapping_properties():
    report = build_sarif_report([finding()], mapping_document())
    run = report["runs"][0]

    assert run["properties"]["complianceFramework"]["name"] == "Example Framework"
    mapping = run["results"][0]["properties"]["complianceMappings"][0]
    assert mapping["control_id"] == "AC-6"
    assert mapping["confidence"] == "partial"


def test_cli_accepts_optional_compliance_mapping_path():
    args = build_parser().parse_args([
        "--source", "fixture",
        "--file", "tests/fixtures",
        "--compliance-mapping", "mappings/nist-sp-800-53-rev5.json",
    ])

    assert args.compliance_mapping == Path("mappings/nist-sp-800-53-rev5.json")
