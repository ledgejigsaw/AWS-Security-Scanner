# WAF and application-edge posture

## Discovery scope

The AWS provider now supports:
- WAFv2 regional Web ACL metadata for the selected scan region.
- WAFv2 CloudFront-scope Web ACL metadata using the global WAF endpoint in `us-east-1`.
- Application Load Balancer metadata and WAF association lookup.
- Existing CloudFront distribution Web ACL association metadata (CloudFront distribution discovery remains implemented separately).

The provider uses paginated `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `elasticloadbalancing:DescribeLoadBalancers` and `wafv2:GetWebACLForResource` calls. It does not change associations, inspect application payloads, send traffic to origins, or assess Network Load Balancers.

## Checks

| ID | Default severity | Behaviour |
|---|---|---|
| WAF-001 | INFO | Review signal when the discovered Web ACL has zero managed rule group statements. Custom rules may still be appropriate. |
| WAF-002 | INFO | Review signal when the discovered Web ACL has zero rate-based statements. Rate limiting is not universally required. |
| ALB-001 | INFO | Review signal when a successful association lookup reports no Web ACL for an Application Load Balancer. |

These are coverage prompts, not proof of exploitability. The scanner counts the presence of managed rule group and rate-based statements; it does not validate rule effectiveness, managed rule versions, exclusions, override actions, rule ordering, scope-down statements or false-positive behaviour.

## Unknown and partial states

A successful WAF association lookup with no Web ACL is represented as `not_associated`. Missing association metadata is not treated as confirmed absence by the rule. API errors are not converted to a clean result; a scan interrupted by permission or service errors should be treated as incomplete.

A Web ACL with no managed group or rate-based rule emits INFO-level review findings only. Organisation policy may decide these are not required or may override severity using the policy mechanism.

## Permissions and regional behaviour

The relevant read-only IAM actions include `wafv2:ListWebACLs`, `wafv2:GetWebACL`, `wafv2:GetWebACLForResource` and `elasticloadbalancing:DescribeLoadBalancers`. CloudFront-scope WAF calls use the WAF global endpoint in `us-east-1`; regional ACL discovery follows the selected scan region.

Tests use mocked API responses. No live AWS account validation is claimed.


## Application Load Balancer TLS policy review

The scanner includes check `ALB-004` for internet-facing ALBs with HTTPS listeners using an explicit snapshot of legacy AWS ELB security policy names known to permit TLS 1.0 and/or TLS 1.1. This is intentionally conservative: missing listener policy metadata and unrecognised policy names remain unclassified rather than being assumed weak. AWS updates policy catalogues over time, so re-check the [official Application Load Balancer security policy documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) before release and refresh the snapshot with tests. The check is a review signal and does not perform TLS handshakes or test live endpoints.
