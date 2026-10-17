from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.models.resource import Resource
from aws_security_scanner.rules.decorators import rule_for


@rule_for(
    "aws_wafv2_web_acl",
    check_id="WAF-001",
    service="WAF",
    severity=Severity.INFO,
    category="Application Edge Security",
    title="WAF Web ACL has no managed rule groups",
    description="No AWS Marketplace or AWS-managed rule group statement was observed in the Web ACL. Custom rules may still provide protection; this is a coverage review signal.",
    remediation="Review whether managed rule groups appropriate to the application and threat model should complement custom rules.",
)
def check_waf_no_managed_rule_groups(resource: Resource) -> list[Finding]:
    if not isinstance(resource.attributes.get("managed_rule_group_count"), int):
        return []
    if resource.attributes["managed_rule_group_count"] > 0:
        return []
    return [Finding.from_rule(
        check_waf_no_managed_rule_groups,
        resource=resource.resource_id,
        region=resource.region,
        evidence="managed_rule_group_count=0",
    )]


@rule_for(
    "aws_wafv2_web_acl",
    check_id="WAF-002",
    service="WAF",
    severity=Severity.INFO,
    category="Application Edge Security",
    title="WAF Web ACL has no rate-based rule",
    description="No rate-based statement was observed in the Web ACL. Whether rate limiting is needed depends on application behaviour and threat model.",
    remediation="Review whether rate-based protection is appropriate for login, API, scraping or resource-exhaustion scenarios.",
)
def check_waf_no_rate_based_rule(resource: Resource) -> list[Finding]:
    if not isinstance(resource.attributes.get("rate_based_rule_count"), int):
        return []
    if resource.attributes["rate_based_rule_count"] > 0:
        return []
    return [Finding.from_rule(
        check_waf_no_rate_based_rule,
        resource=resource.resource_id,
        region=resource.region,
        evidence="rate_based_rule_count=0",
    )]


@rule_for(
    "aws_lb",
    check_id="ALB-001",
    service="ELB",
    severity=Severity.INFO,
    category="Application Edge Security",
    title="Application Load Balancer has no WAF association",
    description="A successful WAF association lookup found no Web ACL associated with this Application Load Balancer. This is a review signal, not proof of exploitable exposure.",
    remediation="Review whether the application requires AWS WAF protection. If so, associate a regional Web ACL with suitable rules and validate expected traffic.",
)
def check_alb_missing_waf_association(resource: Resource) -> list[Finding]:
    if resource.attributes.get("waf_association_state") != "not_associated":
        return []
    return [Finding.from_rule(
        check_alb_missing_waf_association,
        resource=resource.resource_id,
        region=resource.region,
        evidence="GetWebACLForResource returned no WebACL association",
    )]


@rule_for(
    "aws_lb",
    check_id="ALB-002",
    service="ELB",
    severity=Severity.MEDIUM,
    category="Transport Security",
    title="Internet-facing Application Load Balancer has a non-TLS listener",
    description="An internet-facing Application Load Balancer has a discovered listener using HTTP rather than HTTPS.",
    remediation="Review listener exposure and redirect HTTP to HTTPS where appropriate.",
)
def check_alb_non_tls_listener(resource: Resource) -> list[Finding]:
    if resource.attributes.get("scheme") != "internet-facing":
        return []
    listeners = resource.attributes.get("listeners")
    if not isinstance(listeners, list):
        return []
    if not any(isinstance(x, dict) and x.get("protocol") == "HTTP" for x in listeners):
        return []
    return [Finding.from_rule(check_alb_non_tls_listener, resource=resource.resource_id, region=resource.region, evidence="HTTP listener discovered")]


@rule_for(
    "aws_lb",
    check_id="ALB-003",
    service="ELB",
    severity=Severity.MEDIUM,
    category="Logging and Monitoring",
    title="Internet-facing Application Load Balancer access logging is not enabled",
    description="A successful ALB attribute lookup indicates S3 access logging is disabled.",
    remediation="Enable ALB access logging to a dedicated S3 bucket and review its security controls.",
)
def check_alb_access_logging_disabled(resource: Resource) -> list[Finding]:
    if resource.attributes.get("scheme") != "internet-facing":
        return []
    if resource.attributes.get("access_logs_enabled") is not False:
        return []
    return [Finding.from_rule(check_alb_access_logging_disabled, resource=resource.resource_id, region=resource.region, evidence="access_logs.s3.enabled=false")]
