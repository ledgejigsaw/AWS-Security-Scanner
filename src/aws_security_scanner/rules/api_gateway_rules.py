from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_api_gateway_stage",
    check_id="APIGW-001",
    service="API Gateway",
    severity=Severity.HIGH,
    category="Access Control",
    title="API Gateway REST API methods lack authorization",
    description=(
        "At least one discovered REST API method uses authorization type NONE, "
        "and no API resource policy was discovered. This configuration may allow "
        "requests without IAM or a configured authorizer. Some APIs are intentionally "
        "public, so the finding should be reviewed against the endpoint's intended use."
    ),
    remediation=(
        "Confirm whether each affected method is intended to be public. Where access "
        "should be restricted, configure IAM, a suitable authorizer, or a restrictive "
        "API resource policy, and test the deployed stage."
    ),
)
def check_api_gateway_unauthenticated_methods(resource: Resource) -> list[Finding]:
    """Flag NONE-authorized REST API methods only when no resource policy is present."""
    methods = resource.attributes.get("methods")
    if not isinstance(methods, list) or not methods:
        return []
    policy = resource.attributes.get("resource_policy")
    if policy:
        return []
    unauthenticated = [
        method for method in methods
        if isinstance(method, dict)
        and method.get("authorization_type") == "NONE"
    ]
    if not unauthenticated:
        return []
    evidence_methods = ", ".join(
        f"{method.get('http_method', '?')} {method.get('path', '?')}"
        for method in unauthenticated[:10]
    )
    return [Finding.from_rule(
        check_api_gateway_unauthenticated_methods,
        resource=resource.resource_id,
        region=resource.region,
        evidence=(
            f"{len(unauthenticated)} method(s) use authorizationType=NONE; "
            f"no API resource policy was discovered; methods: {evidence_methods}"
        ),
    )]


@rule_for(
    "aws_api_gateway_stage",
    check_id="APIGW-002",
    service="API Gateway",
    severity=Severity.MEDIUM,
    category="Logging and Monitoring",
    title="API Gateway REST API stage access logging is not configured",
    description=(
        "The stage does not have both an access-log destination and a log format "
        "configured in its discovered accessLogSettings. Access logs support "
        "investigation, monitoring and auditability."
    ),
    remediation=(
        "Configure stage access logging to a managed CloudWatch Logs destination "
        "with a structured format containing useful request and response context. "
        "Avoid logging secrets, authorization headers or other sensitive values."
    ),
)
def check_api_gateway_access_logging_disabled(resource: Resource) -> list[Finding]:
    """Flag stages only when complete discovery confirms access logging is absent."""
    if resource.attributes.get("access_logging_enabled") is not False:
        return []
    return [Finding.from_rule(
        check_api_gateway_access_logging_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence=(
            "access_log_destination_arn="
            f"{resource.attributes.get('access_log_destination_arn')!r}; "
            f"access_log_format={resource.attributes.get('access_log_format')!r}"
        ),
    )]


@rule_for(
    "aws_api_gateway_http_api_stage",
    check_id="APIGW-003",
    service="API Gateway",
    severity=Severity.HIGH,
    category="Access Control",
    title="API Gateway HTTP API route lacks authorization",
    description="A discovered HTTP API route uses NONE authorization. Public routes may be intentional, so the endpoint should be reviewed against its intended exposure.",
    remediation="Confirm whether the route is intended to be public. Where access should be restricted, configure IAM or an appropriate JWT/Lambda authorizer and redeploy the stage.",
)
def check_api_gateway_http_api_unauthenticated_routes(resource: Resource) -> list[Finding]:
    routes = resource.attributes.get("routes")
    if not isinstance(routes, list):
        return []
    unauthenticated = [
        route for route in routes
        if isinstance(route, dict) and route.get("authorization_type") == "NONE"
    ]
    if not unauthenticated:
        return []
    evidence = ", ".join(str(route.get("route_key", "?")) for route in unauthenticated[:10])
    return [Finding.from_rule(
        check_api_gateway_http_api_unauthenticated_routes,
        resource=resource.resource_id,
        region=resource.region,
        evidence=f"{len(unauthenticated)} route(s) use AuthorizationType=NONE; routes: {evidence}",
    )]


@rule_for(
    "aws_api_gateway_http_api_stage",
    check_id="APIGW-004",
    service="API Gateway",
    severity=Severity.MEDIUM,
    category="Logging and Monitoring",
    title="API Gateway HTTP API stage access logging is not configured",
    description="The HTTP API stage does not have both an access-log destination and format configured.",
    remediation="Configure HTTP API stage access logging to a CloudWatch Logs destination using a structured format that avoids secrets and authorization headers.",
)
def check_api_gateway_http_api_access_logging_disabled(resource: Resource) -> list[Finding]:
    if resource.attributes.get("access_logging_enabled") is not False:
        return []
    return [Finding.from_rule(
        check_api_gateway_http_api_access_logging_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence=(
            "access_log_destination_arn="
            f"{resource.attributes.get('access_log_destination_arn')!r}; "
            f"access_log_format={resource.attributes.get('access_log_format')!r}"
        ),
    )]
