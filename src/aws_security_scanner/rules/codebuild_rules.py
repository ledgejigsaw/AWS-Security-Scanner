import re

from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


_SENSITIVE_ENV_NAME = re.compile(r"(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)", re.IGNORECASE)


@rule_for(
    "aws_codebuild_project",
    check_id="CB-001",
    service="CodeBuild",
    severity=Severity.MEDIUM,
    category="Build Security",
    title="CodeBuild project enables privileged build mode",
    description="The CodeBuild environment explicitly enables privileged mode. This is commonly required for some container-build workflows but increases the impact of a compromised build.",
    remediation="Disable privileged mode unless required by the build design; isolate the project, scope its service role and restrict build-source trust where privileged mode is necessary.",
)
def check_codebuild_privileged_mode(resource: Resource) -> list[Finding]:
    if resource.attributes.get("privileged_mode") is not True:
        return []
    return [Finding.from_rule(
        check_codebuild_privileged_mode,
        resource=resource.resource_id,
        region=resource.region,
        evidence="privileged_mode=true",
    )]


@rule_for(
    "aws_codebuild_project",
    check_id="CB-002",
    service="CodeBuild",
    severity=Severity.MEDIUM,
    category="Secrets Management",
    title="CodeBuild project declares sensitive-looking environment variable names as plaintext",
    description="One or more environment variables have names commonly associated with credentials and are explicitly configured as PLAINTEXT. Values are never collected or reported by this scanner.",
    remediation="Store sensitive values in Secrets Manager or Systems Manager Parameter Store and reference them using the corresponding CodeBuild environment-variable type.",
)
def check_codebuild_plaintext_sensitive_environment_variables(resource: Resource) -> list[Finding]:
    variables = resource.attributes.get("environment_variables", [])
    if not isinstance(variables, list):
        return []
    flagged = sorted({
        item["name"]
        for item in variables
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and _SENSITIVE_ENV_NAME.search(item["name"])
        and str(item.get("type", "")).upper() == "PLAINTEXT"
    })
    if not flagged:
        return []
    return [Finding.from_rule(
        check_codebuild_plaintext_sensitive_environment_variables,
        resource=resource.resource_id,
        region=resource.region,
        evidence="plaintext_sensitive_variable_names=" + ",".join(flagged),
    )]
