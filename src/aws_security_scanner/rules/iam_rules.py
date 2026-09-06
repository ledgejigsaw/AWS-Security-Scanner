from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for("aws_iam_policy")
def check_overly_permissive_policy(
    resource: Resource,
) -> list[Finding]:
    """Detect IAM policies granting unrestricted permissions."""

    findings = []

    policy = resource.attributes.get("policy_document")

    if not policy:
        return findings

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if (
            statement.get("Effect") == "Allow"
            and statement.get("Action") == "*"
            and statement.get("Resource") == "*"
        ):
            findings.append(
                Finding(
                    check_id="IAM-001",
                    severity=Severity.CRITICAL,
                    service="IAM",
                    resource=resource.resource_id,
                    title="IAM policy grants unrestricted permissions",
                    description=(
                        "The IAM policy contains an Allow statement "
                        "granting all actions against all resources. "
                        "This provides unrestricted permissions and "
                        "creates a significant privilege escalation "
                        "and compromise risk."
                    ),
                    remediation=(
                        "Apply the principle of least privilege. "
                        "Restrict the allowed actions to only those "
                        "required and limit Resource to the specific "
                        "AWS resources that require access."
                    ),
                    region=resource.region,
                    evidence="Effect=Allow, Action=*, Resource=*",
                )
            )

    return findings