from datetime import date

from aws_security_scanner.models.finding import Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.lambda_rules import check_lambda_deprecated_runtime
from aws_security_scanner.rules.lambda_runtime_lifecycle import deprecated_runtime_date


def lambda_resource(runtime):
    return Resource(
        resource_type="aws_lambda_function",
        resource_id="example-function",
        attributes={"runtime": runtime},
        source="fixture",
        region="eu-west-2",
    )


def test_known_deprecated_runtime_generates_high_finding():
    findings = check_lambda_deprecated_runtime(lambda_resource("python3.9"))
    assert len(findings) == 1
    assert findings[0].check_id == "LAMBDA-003"
    assert findings[0].severity == Severity.HIGH
    assert "deprecation_date=2025-12-15" in findings[0].evidence
    assert "lifecycle_data_reviewed_on=2026-10-12" in findings[0].evidence


def test_unknown_custom_and_missing_runtime_do_not_generate_finding():
    assert check_lambda_deprecated_runtime(lambda_resource("provided.al2023")) == []
    assert check_lambda_deprecated_runtime(lambda_resource("custom.runtime")) == []
    assert check_lambda_deprecated_runtime(lambda_resource(None)) == []


def test_runtime_is_not_deprecated_before_recorded_date():
    assert deprecated_runtime_date("nodejs20.x", as_of=date(2026, 4, 29)) is None
    assert deprecated_runtime_date("nodejs20.x", as_of=date(2026, 4, 30)) == date(2026, 4, 30)


def test_future_scheduled_deprecation_is_not_reported_as_deprecated():
    # Python 3.10's scheduled deprecation is not in the deprecated snapshot
    # as of the recorded review date; unknown/future states stay unflagged.
    assert deprecated_runtime_date("python3.10", as_of=date(2026, 10, 12)) is None
