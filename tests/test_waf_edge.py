from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.rules.waf_rules import (
    check_alb_missing_waf_association,
    check_waf_no_managed_rule_groups,
    check_waf_no_rate_based_rule,
)


def resource(resource_type, resource_id, **attributes):
    return Resource(resource_type=resource_type, resource_id=resource_id,
                    attributes=attributes, source="fixture", region="eu-west-2")


def test_waf_rule_checks_are_review_signals_and_ignore_unknown_states():
    acl = resource("aws_wafv2_web_acl", "acl-1", managed_rule_group_count=0, rate_based_rule_count=0)
    assert check_waf_no_managed_rule_groups(acl)[0].check_id == "WAF-001"
    assert check_waf_no_rate_based_rule(acl)[0].check_id == "WAF-002"
    assert check_waf_no_managed_rule_groups(resource("aws_wafv2_web_acl", "acl-1", managed_rule_group_count=2)) == []
    assert check_waf_no_rate_based_rule(resource("aws_wafv2_web_acl", "acl-1", rate_based_rule_count=1)) == []
    assert check_waf_no_managed_rule_groups(resource("aws_wafv2_web_acl", "acl-1")) == []
    assert check_waf_no_rate_based_rule(resource("aws_wafv2_web_acl", "acl-1")) == []


def test_alb_missing_waf_rule_only_flags_confirmed_absence():
    assert check_alb_missing_waf_association(resource("aws_lb", "alb-1", waf_association_state="not_associated"))[0].check_id == "ALB-001"
    assert check_alb_missing_waf_association(resource("aws_lb", "alb-1", waf_association_state="associated")) == []
    assert check_alb_missing_waf_association(resource("aws_lb", "alb-1")) == []


def test_waf_provider_paginates_and_normalises_acl_rule_types(monkeypatch):
    class WAF:
        def list_web_acls(self, **kwargs):
            if kwargs.get("NextMarker") == "page-2":
                return {"WebACLs": [{"Name": "regional-two", "Id": "acl-2"}]}
            return {"WebACLs": [{"Name": "regional-one", "Id": "acl-1"}], "NextMarker": "page-2"}

        def get_web_acl(self, **kwargs):
            if kwargs["Id"] == "acl-1":
                return {"WebACL": {
                    "Id": "acl-1", "ARN": "arn:aws:wafv2:eu-west-2:123:regional/webacl/one/acl-1",
                    "Rules": [
                        {"Statement": {"ManagedRuleGroupStatement": {"Name": "AWSManagedRulesCommonRuleSet"}}},
                        {"Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}}},
                    ],
                    "DefaultAction": {"Allow": {}},
                }}
            return {"WebACL": {"Id": "acl-2", "ARN": "arn:aws:wafv2:eu-west-2:123:regional/webacl/two/acl-2", "Rules": [], "DefaultAction": {"Block": {}}}}

    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: object())
    provider = AWSProvider(wafv2_client=WAF(), wafv2_global_client=WAF(), region="eu-west-2")
    acls = provider.discover_waf_web_acls("REGIONAL")
    assert len(acls) == 2
    assert acls[0].attributes["managed_rule_group_count"] == 1
    assert acls[0].attributes["rate_based_rule_count"] == 1
    assert acls[0].attributes["default_action"] == "allow"
    assert acls[1].attributes["default_action"] == "block"


def test_alb_provider_ignores_network_load_balancers_and_normalises_association(monkeypatch):
    class ELB:
        def describe_load_balancers(self, **kwargs):
            return {"LoadBalancers": [
                {"Type": "application", "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-2:123:loadbalancer/app/one/1", "LoadBalancerName": "one", "Scheme": "internet-facing", "VpcId": "vpc-1"},
                {"Type": "network", "LoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-2:123:loadbalancer/net/two/2", "LoadBalancerName": "two"},
            ]}

    class WAF:
        def get_web_acl_for_resource(self, **kwargs):
            return {}

    monkeypatch.setattr("aws_security_scanner.providers.aws.boto3.client", lambda *args, **kwargs: object())
    provider = AWSProvider(elbv2_client=ELB(), wafv2_client=WAF(), region="eu-west-2")
    lbs = provider.discover_application_load_balancers()
    assert len(lbs) == 1
    assert lbs[0].attributes["waf_association_state"] == "not_associated"
    assert lbs[0].attributes["scheme"] == "internet-facing"
