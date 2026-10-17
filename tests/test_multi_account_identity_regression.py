from aws_security_scanner.baseline_history import finding_fingerprint, write_baseline
from aws_security_scanner.graph import build_resource_graph
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource


ACCOUNT_A = "111111111111"
ACCOUNT_B = "222222222222"


def account_finding(account_id):
    return Finding(
        check_id="S3-001",
        severity=Severity.CRITICAL,
        service="S3",
        resource="shared-name",
        title="Public bucket",
        description="Bucket has public access",
        remediation="Restrict public access",
        region="eu-west-2",
        account_id=account_id,
    )


def test_duplicate_resource_names_remain_separate_across_accounts():
    resources = [
        Resource(
            resource_type="aws_s3_bucket",
            resource_id="shared-name",
            attributes={},
            source="aws",
            region="eu-west-2",
            account_id=ACCOUNT_A,
        ),
        Resource(
            resource_type="aws_s3_bucket",
            resource_id="shared-name",
            attributes={},
            source="aws",
            region="eu-west-2",
            account_id=ACCOUNT_B,
        ),
    ]
    findings = [account_finding(ACCOUNT_A), account_finding(ACCOUNT_B)]

    graph = build_resource_graph(resources, findings)

    assert len(graph["nodes"]) == 2
    nodes_by_account = {node["account_id"]: node for node in graph["nodes"]}
    assert set(nodes_by_account) == {ACCOUNT_A, ACCOUNT_B}
    assert nodes_by_account[ACCOUNT_A]["findings"] == [
        {"check_id": "S3-001", "severity": "CRITICAL"}
    ]
    assert nodes_by_account[ACCOUNT_B]["findings"] == [
        {"check_id": "S3-001", "severity": "CRITICAL"}
    ]


def test_baseline_identity_does_not_collapse_same_resource_across_accounts(tmp_path):
    findings = [account_finding(ACCOUNT_A), account_finding(ACCOUNT_B)]

    fingerprints = {finding_fingerprint(item) for item in findings}
    assert len(fingerprints) == 2

    output = tmp_path / "baseline.json"
    write_baseline(findings, output)
    import json

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload["findings"]) == 2
    assert {item["account_id"] for item in payload["findings"]} == {ACCOUNT_A, ACCOUNT_B}
