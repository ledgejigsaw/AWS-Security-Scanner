from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


WEAK_CLOUDFRONT_TLS_POLICIES = {
    "SSLv3",
    "TLSv1",
    "TLSv1_2016",
    "TLSv1.1_2016",
}


@rule_for(
    "aws_cloudfront_distribution",
    check_id="CLOUDFRONT-001",
    service="CloudFront",
    severity=Severity.HIGH,
    category="Transport Security",
    title="CloudFront permits HTTP viewer connections",
    description=(
        "At least one discovered cache behaviour does not require HTTPS "
        "for viewer requests. HTTP access can expose requests to interception "
        "unless the distribution redirects viewers to HTTPS."
    ),
    remediation=(
        "Set the default and every cache behaviour to Redirect HTTP to HTTPS "
        "or HTTPS Only, according to application requirements."
    ),
)
def check_cloudfront_http_viewer_access(resource: Resource) -> list[Finding]:
    policies = resource.attributes.get("viewer_protocol_policies")
    if not isinstance(policies, list) or not policies:
        return []
    insecure = [policy for policy in policies if policy not in {"redirect-to-https", "https-only"}]
    if not insecure:
        return []
    return [Finding.from_rule(
        check_cloudfront_http_viewer_access,
        resource=resource.resource_id,
        region=resource.region,
        evidence=f"ViewerProtocolPolicy values not enforcing HTTPS: {', '.join(map(str, insecure))}",
    )]


@rule_for(
    "aws_cloudfront_distribution",
    check_id="CLOUDFRONT-002",
    service="CloudFront",
    severity=Severity.HIGH,
    category="Transport Security",
    title="CloudFront uses a weak minimum TLS policy",
    description=(
        "The distribution's viewer certificate is configured with a legacy "
        "TLS policy. This may permit obsolete protocol versions."
    ),
    remediation=(
        "Choose a current CloudFront security policy that meets the application's "
        "compatibility requirements and your organisation's TLS baseline."
    ),
)
def check_cloudfront_weak_tls_policy(resource: Resource) -> list[Finding]:
    policy = resource.attributes.get("minimum_protocol_version")
    if not isinstance(policy, str) or not policy:
        return []
    if policy not in WEAK_CLOUDFRONT_TLS_POLICIES:
        return []
    return [Finding.from_rule(
        check_cloudfront_weak_tls_policy,
        resource=resource.resource_id,
        region=resource.region,
        evidence=f"MinimumProtocolVersion={policy}",
    )]


@rule_for(
    "aws_cloudfront_distribution",
    check_id="CLOUDFRONT-003",
    service="CloudFront",
    severity=Severity.MEDIUM,
    category="Logging and Monitoring",
    title="CloudFront access logging is not enabled",
    description=(
        "CloudFront access logging is explicitly disabled. This reduces the "
        "available evidence for investigating viewer requests and abuse."
    ),
    remediation=(
        "Enable appropriate CloudFront access logging and configure a protected "
        "destination with retention aligned to operational and regulatory needs."
    ),
)
def check_cloudfront_logging_disabled(resource: Resource) -> list[Finding]:
    if resource.attributes.get("logging_enabled") is not False:
        return []
    return [Finding.from_rule(
        check_cloudfront_logging_disabled,
        resource=resource.resource_id,
        region=resource.region,
        evidence="CloudFront Logging.Enabled=false",
    )]


@rule_for(
    "aws_cloudfront_distribution",
    check_id="CLOUDFRONT-004",
    service="CloudFront",
    severity=Severity.INFO,
    category="Application Edge Protection",
    title="CloudFront distribution has no associated WAF Web ACL",
    description=(
        "No Web ACL association was returned for the distribution. Whether WAF "
        "is required depends on application exposure, threat model and other controls."
    ),
    remediation=(
        "Review whether AWS WAF is appropriate for this distribution. If required, "
        "associate a suitable Web ACL and validate its rules against expected traffic."
    ),
)
def check_cloudfront_missing_waf(resource: Resource) -> list[Finding]:
    if "web_acl_id" not in resource.attributes:
        return []
    if resource.attributes.get("web_acl_id"):
        return []
    return [Finding.from_rule(
        check_cloudfront_missing_waf,
        resource=resource.resource_id,
        region=resource.region,
        evidence="CloudFront WebACLId is absent or empty; review whether WAF is required",
    )]
