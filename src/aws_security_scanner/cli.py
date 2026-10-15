import argparse
import json
import sys
from pathlib import Path

import boto3

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.integrations.securityhub import securityhub_to_finding
from aws_security_scanner.integrations.guardduty import guardduty_to_finding
from aws_security_scanner.integrations.access_analyzer import access_analyzer_to_finding
from aws_security_scanner.multi_account import run_multi_account_scan
from aws_security_scanner.graph import write_resource_graph
from aws_security_scanner.reporting.json_reporter import write_json_report
from aws_security_scanner.reporting.html_reporter import write_html_report
from aws_security_scanner.reporting.sarif_reporter import write_sarif_report
from aws_security_scanner.rules.registry import get_all_rules
from aws_security_scanner.policy import SecurityPolicy
from aws_security_scanner.models.finding import Finding, Severity
from aws_security_scanner.baseline_history import (
    active_baseline_fingerprints,
    diff_findings,
    load_baseline_records,
    write_baseline as write_history_baseline,
)
from aws_security_scanner.compliance import ComplianceMappingError, load_mapping_file
from aws_security_scanner.triage import (
    exclude_baselined_findings,
    filter_by_minimum_severity,
    load_baseline,
    write_baseline,
)



def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="AWS cloud security posture assessment tool."
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Ask guided questions to configure and confirm a scan; cannot be combined with scan options.",
    )

    parser.add_argument(
        "--source",
        choices=["fixture", "terraform", "hcl", "aws"],
        required=False,
        help="Security resource source (omit only when using --interactive).",
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Fixture directory, Terraform JSON file or Terraform HCL source file.",
    )
    parser.add_argument(
        "--accounts-file",
        type=Path,
        help="Opt-in JSON list of account IDs and cross-account audit role ARNs (AWS source only).",
    )

    parser.add_argument(
        "--region",
        help="AWS region to scan.",
    )
    parser.add_argument(
        "--profile",
        help="AWS shared-config profile to use (AWS source only; no credentials are accepted on the command line).",
    )
    parser.add_argument(
        "--service",
        action="append",
        choices=[
            "s3", "iam", "ec2", "ebs", "vpc", "cloudtrail", "kms", "rds",
            "lambda", "secretsmanager", "ecr", "dynamodb", "sqs", "sns",
            "apigateway", "ecs", "cloudfront", "waf", "elb", "securityhub", "guardduty", "config",
        ],
        help="Limit AWS discovery to selected service domains; repeat to select multiple. Default: all supported domains.",
    )

    parser.add_argument(
        "--include-native-findings",
        action="store_true",
        help="Import bounded native Security Hub, GuardDuty and IAM Access Analyzer findings (AWS source only).",
    )
    parser.add_argument(
        "--native-findings-limit",
        type=int,
        default=100,
        help="Maximum findings to import per native source (1-1000; default: 100).",
    )

    parser.add_argument(
        "--format",
        choices=["json", "html", "sarif"],
        default="json",
        help="Report output format.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for the generated report.",
    )
    parser.add_argument(
        "--graph-output",
        type=Path,
        help="Optional path for deterministic resource-graph JSON (single-account scans only).",
    )

    parser.add_argument(
    "--policy",
    type=Path,
    help="Path to a YAML security policy file.",
)

    parser.add_argument(
        "--compliance-mapping",
        type=Path,
        help="Optional versioned JSON control-mapping file to annotate reports.",
    )

    parser.add_argument(
        "--min-severity",
        choices=[severity.value for severity in Severity],
        default=None,
        help="Only include findings at this severity or higher.",
    )

    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--baseline",
        type=Path,
        help="Suppress findings already recorded in a baseline JSON file.",
    )
    baseline_group.add_argument(
        "--write-baseline",
        type=Path,
        help="Write current finding identities to a version 2 baseline JSON file.",
    )
    parser.add_argument(
        "--compare-baseline",
        type=Path,
        help="Compare current findings with a version 1 or 2 baseline without suppressing findings.",
    )
    parser.add_argument(
        "--diff-output",
        type=Path,
        help="Path for the JSON baseline diff (requires --compare-baseline).",
    )

    return parser


def discover_resources(
    source: str,
    source_path: Path | None = None,
    region: str | None = None,
    aws_session=None,
    account_id: str | None = None,
    services: list[str] | None = None,
):
    """Discover resources from the selected source."""

    if source == "fixture":
        if source_path is None:
            raise ValueError(
                "--file is required when using the fixture source."
            )

        provider = FixtureProvider(source_path)
        return provider.discover()

    if source == "terraform":
        if source_path is None:
            raise ValueError(
                "--file is required when using the terraform source."
            )

        provider = TerraformProvider(source_path)
        resources = provider.discover()
        return aggregate_s3_resources(resources)

    if source == "hcl":
        if source_path is None:
            raise ValueError("--file is required when using the hcl source.")
        provider = TerraformHCLProvider(source_path)
        return aggregate_s3_resources(provider.discover())

    if source == "aws":
        provider = (
            AWSProvider(region=region, session=aws_session)
            if aws_session is not None
            else AWSProvider(region=region)
        )

        discovery_by_service = {
            "s3": [provider.discover_s3_buckets],
            "iam": [provider.discover_iam_policies, provider.discover_iam_roles, provider.discover_iam_users, provider.discover_iam_account],
            "ec2": [provider.discover_ec2_instances],
            "ebs": [provider.discover_ebs_volumes, provider.discover_ebs_snapshots],
            "vpc": [provider.discover_security_groups, provider.discover_vpcs, provider.discover_subnets, provider.discover_route_tables, provider.discover_network_acls, provider.discover_flow_logs],
            "cloudtrail": [provider.discover_cloudtrail_trails],
            "kms": [provider.discover_kms_keys],
            "rds": [provider.discover_rds_instances],
            "lambda": [provider.discover_lambda_functions],
            "secretsmanager": [provider.discover_secrets_manager_secrets],
            "ecr": [provider.discover_ecr_repositories],
            "dynamodb": [provider.discover_dynamodb_tables],
            "sqs": [provider.discover_sqs_queues],
            "sns": [provider.discover_sns_topics],
            "apigateway": [provider.discover_api_gateway_rest_apis],
            "ecs": [provider.discover_ecs_task_definitions, provider.discover_ecs_services],
            "cloudfront": [provider.discover_cloudfront_distributions],
            "waf": [lambda: provider.discover_waf_web_acls("CLOUDFRONT"), lambda: provider.discover_waf_web_acls("REGIONAL")],
            "elb": [provider.discover_application_load_balancers],
            "securityhub": [provider.discover_security_hub],
            "guardduty": [provider.discover_guardduty],
            "config": [provider.discover_aws_config],
        }
        selected_services = list(dict.fromkeys(services)) if services else list(discovery_by_service)
        resources = []
        for service in selected_services:
            for discover in discovery_by_service[service]:
                resources.extend(discover())

        if account_id is not None:
            for resource in resources:
                resource.account_id = account_id

        return resources


def run_scan(
    source: str,
    source_path: Path | None = None,
    policy_path: Path | None = None,
    region: str | None = None,
    include_native_findings: bool = False,
    native_findings_limit: int = 100,
    aws_session=None,
    expected_account_id: str | None = None,
    profile: str | None = None,
    services: list[str] | None = None,
    return_resources: bool = False,
) -> list | tuple[list, list]:
    if include_native_findings and source != "aws":
        raise ValueError("--include-native-findings can only be used with --source aws.")
    if (profile or services) and source != "aws":
        raise ValueError("--profile and --service can only be used with --source aws.")
    if profile and aws_session is not None:
        raise ValueError("--profile cannot be combined with an injected AWS session.")
    if services:
        valid_services = {
            "s3", "iam", "ec2", "ebs", "vpc", "cloudtrail", "kms", "rds",
            "lambda", "secretsmanager", "ecr", "dynamodb", "sqs", "sns",
            "apigateway", "ecs", "cloudfront", "waf", "elb", "securityhub", "guardduty", "config",
        }
        unknown = sorted(set(services) - valid_services)
        if unknown:
            raise ValueError(f"Unsupported AWS service selection: {', '.join(unknown)}")
    if include_native_findings and (
        isinstance(native_findings_limit, bool)
        or not isinstance(native_findings_limit, int)
        or not 1 <= native_findings_limit <= 1000
    ):
        raise ValueError("--native-findings-limit must be between 1 and 1000.")

    if profile is not None:
        aws_session = boto3.Session(profile_name=profile, region_name=region)
    if aws_session is None and expected_account_id is None and services is None:
        resources = discover_resources(source, source_path, region)
    else:
        resources = discover_resources(
            source,
            source_path,
            region,
            aws_session,
            expected_account_id,
            services,
        )

    policy = (
        SecurityPolicy.from_yaml(policy_path)
        if policy_path
        else SecurityPolicy()
    )

    engine = RuleEngine(
        get_all_rules(),
        policy=policy,
    )

    findings = engine.scan(resources)
    if source == "hcl":
        for resource in resources:
            unresolved = resource.attributes.get("hcl_unresolved_expressions")
            diagnostic = resource.attributes.get("hcl_diagnostic")
            if not unresolved and diagnostic != "module_not_expanded":
                continue
            is_module = diagnostic == "module_not_expanded"
            findings.append(
                Finding(
                    check_id="IAC-HCL-002" if is_module else "IAC-HCL-001",
                    severity=Severity.INFO,
                    service="Terraform HCL",
                    resource=resource.resource_id,
                    title=(
                        "Terraform module was not expanded"
                        if is_module
                        else "Terraform HCL contains unresolved expressions"
                    ),
                    description=(
                        "The scanner does not load or evaluate Terraform modules; resources inside this module are outside this scan."
                        if is_module
                        else "One or more HCL expressions could not be resolved statically. Related checks may be incomplete."
                    ),
                    remediation=(
                        "Provide Terraform JSON generated from a reviewed plan for expanded module resources, or review the module source separately."
                        if is_module
                        else "Resolve the expression from a trusted, reviewed plan or inspect the referenced values before relying on this assessment."
                    ),
                    region=resource.region,
                    evidence="; ".join(str(item) for item in (unresolved or [])[:5]) or "Module contents were not loaded.",
                )
            )

    if include_native_findings:
        # Keep native finding ingestion opt-in. A separate provider instance
        # avoids changing the existing discovery call contract for normal scans.
        native_provider = (
            AWSProvider(region=region, session=aws_session)
            if aws_session is not None
            else AWSProvider(region=region)
        )
        native_items = native_provider.get_securityhub_findings(limit=native_findings_limit)
        for item in native_items:
            # GuardDuty's direct API below is the canonical source for GuardDuty
            # findings; avoid importing the same product again through Security Hub.
            product_name = item.get("ProductName") if isinstance(item, dict) else None
            product_arn = item.get("ProductArn", "") if isinstance(item, dict) else ""
            if product_name == "GuardDuty" or (
                isinstance(product_arn, str) and "/product/aws/guardduty" in product_arn
            ):
                continue
            converted = securityhub_to_finding(item, fallback_region=region)
            if converted is not None:
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                findings.append(converted)

        guardduty_items = native_provider.get_guardduty_findings(limit=native_findings_limit)
        for item in guardduty_items:
            converted = guardduty_to_finding(item, fallback_region=region)
            if converted is not None:
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                findings.append(converted)

        access_analyzer_items = native_provider.get_access_analyzer_findings(
            limit=native_findings_limit
        )
        for item in access_analyzer_items:
            converted = access_analyzer_to_finding(item, fallback_region=region)
            if converted is not None:
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                findings.append(converted)

    return (findings, resources) if return_resources else findings


def main() -> None:
    """Run the AWS Security Scanner CLI."""

    parser = build_parser()
    args = parser.parse_args()

    if args.interactive:
        if sys.argv[1:] != ["--interactive"]:
            parser.error("--interactive must be used by itself; answer the guided prompts instead")
        from aws_security_scanner.interactive import build_interactive_args

        interactive_args = build_interactive_args()
        if interactive_args is None:
            return
        args = parser.parse_args(interactive_args)
    elif args.source is None:
        parser.error("--source is required unless --interactive is used")

    if args.diff_output and not args.compare_baseline:
        parser.error("--diff-output requires --compare-baseline")
    if args.include_native_findings and args.source != "aws":
        parser.error("--include-native-findings can only be used with --source aws")
    if args.accounts_file and args.source != "aws":
        parser.error("--accounts-file can only be used with --source aws")
    if args.accounts_file and args.file:
        parser.error("--accounts-file cannot be combined with --file")
    if (args.profile or args.service) and args.source != "aws":
        parser.error("--profile and --service can only be used with --source aws")
    if args.accounts_file and args.profile:
        parser.error("--profile with --accounts-file is not supported; configure the default credential chain for the caller")
    if args.graph_output and args.accounts_file:
        parser.error("--graph-output is not yet supported with --accounts-file")
    if not 1 <= args.native_findings_limit <= 1000:
        parser.error("--native-findings-limit must be between 1 and 1000")
    if args.native_findings_limit != 100 and not args.include_native_findings:
        parser.error("--native-findings-limit requires --include-native-findings")

    compliance_mapping = None
    if args.compliance_mapping:
        registered_check_ids = {
            rule.metadata.check_id for rule in get_all_rules()
        }
        try:
            compliance_mapping = load_mapping_file(
                args.compliance_mapping, registered_check_ids
            )
        except ComplianceMappingError as exc:
            parser.error(str(exc))

    assessment_metadata = None
    graph_resources = None
    if args.accounts_file:
        findings, assessment_metadata = run_multi_account_scan(
            args.accounts_file,
            region=args.region,
            scan_function=run_scan,
            policy_path=args.policy,
            include_native_findings=args.include_native_findings,
            native_findings_limit=args.native_findings_limit,
        )
    else:
        scan_result = run_scan(
            args.source,
            args.file,
            args.policy,
            args.region,
            args.include_native_findings,
            args.native_findings_limit,
            profile=args.profile,
            services=args.service,
            return_resources=bool(args.graph_output),
        )
        if args.graph_output:
            findings, graph_resources = scan_result
        else:
            findings = scan_result

    baseline_action_requested = bool(
        args.write_baseline or args.compare_baseline or args.baseline
    )
    baseline_actions_skipped = bool(
        assessment_metadata
        and assessment_metadata["summary"]["failed_accounts"] > 0
        and baseline_action_requested
    )
    if baseline_actions_skipped:
        print(
            "Warning: baseline write/compare/suppression skipped because one or more "
            "accounts failed; partial results must not mark unseen findings as resolved."
        )

    if args.write_baseline and not baseline_actions_skipped:
        write_history_baseline(findings, args.write_baseline)

    if args.compare_baseline and not baseline_actions_skipped:
        records = load_baseline_records(args.compare_baseline)
        diff = diff_findings(findings, records)
        diff_path = args.diff_output or Path("reports/baseline-diff.json")
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff_path.write_text(json.dumps(diff, indent=2) + "\n", encoding="utf-8")
        print(
            "Baseline comparison complete. "
            f"New: {len(diff['new'])}, resolved: {len(diff['resolved'])}, "
            f"unchanged: {len(diff['unchanged'])}. Diff written to {diff_path}"
        )

    if args.baseline and not baseline_actions_skipped:
        records = load_baseline_records(args.baseline)
        findings = exclude_baselined_findings(
            findings,
            active_baseline_fingerprints(records),
        )

    findings = filter_by_minimum_severity(findings, args.min_severity)

    output_path = args.output or Path(
        "reports/scan.html"
        if args.format == "html"
        else "reports/scan.sarif"
        if args.format == "sarif"
        else "reports/scan.json"
    )

    if args.graph_output and graph_resources is not None:
        write_resource_graph(graph_resources, findings, args.graph_output)
        print(f"Resource graph written to {args.graph_output}")

    if args.format == "json":
        write_json_report(findings, output_path, compliance_mapping, assessment_metadata)
    elif args.format == "html":
        write_html_report(findings, output_path, compliance_mapping, assessment_metadata)
    else:
        write_sarif_report(findings, output_path, compliance_mapping, assessment_metadata)

    print(
        f"Security scan complete. "
        f"{len(findings)} findings written to {output_path}"
    )
    if baseline_actions_skipped:
        raise SystemExit(2)
    if assessment_metadata and assessment_metadata["summary"]["failed_accounts"] > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()