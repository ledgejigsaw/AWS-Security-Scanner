import argparse
import json
import sys
from pathlib import Path
from time import perf_counter

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.integrations.securityhub import securityhub_to_finding
from aws_security_scanner.integrations.guardduty import guardduty_to_finding
from aws_security_scanner.integrations.access_analyzer import access_analyzer_to_finding
from aws_security_scanner.integrations.inspector import inspector_to_finding
from aws_security_scanner.integrations.macie import macie_to_finding
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
from aws_security_scanner.risk import RiskScoringConfigError, load_risk_config, score_findings
from aws_security_scanner.triage import (
    exclude_baselined_findings,
    filter_by_minimum_severity,
    load_baseline,
    write_baseline,
)
from aws_security_scanner.scan_summary import (
    build_scan_summary,
    threshold_is_met,
    scan_exit_code,
    write_scan_summary,
)




def create_verified_aws_session(profile: str | None, region: str | None):
    """Resolve configured AWS credentials and verify the active identity via STS.

    Credentials are never requested interactively or accepted as CLI arguments.
    AWS CLI profiles, IAM Identity Center, environment variables, and supported
    workload credential providers remain the responsibility of boto3's chain.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        identity = session.client("sts", region_name=region or "us-east-1").get_caller_identity()
    except (NoCredentialsError, PartialCredentialsError):
        raise RuntimeError(
            "No usable AWS credentials were found. Configure a read-only profile "
            "with 'aws configure', sign in with 'aws configure sso' and 'aws sso login "
            "--profile PROFILE', or use an approved environment/workload credential "
            "provider. Do not paste credentials into the scanner."
        ) from None
    except ProfileNotFound:
        raise RuntimeError(
            f"AWS profile {profile!r} was not found. Check ~/.aws/config and "
            "~/.aws/credentials, or create the profile with 'aws configure' / "
            "'aws configure sso'."
        ) from None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "AWSClientError")
        raise RuntimeError(
            f"AWS identity verification failed ({code}). Check credential validity "
            "and network access, then retry. No scan was started."
        ) from None
    except BotoCoreError:
        raise RuntimeError(
            "AWS identity verification could not complete because the credential "
            "provider or AWS endpoint was unavailable. Check your AWS SSO login, "
            "credential configuration and network access. No scan was started."
        ) from None

    account_id = identity.get("Account") if isinstance(identity, dict) else None
    arn = identity.get("Arn") if isinstance(identity, dict) else None
    if (
        not isinstance(account_id, str)
        or len(account_id) != 12
        or not account_id.isdigit()
        or not isinstance(arn, str)
        or not arn
    ):
        raise RuntimeError(
            "AWS STS returned an incomplete identity response. No scan was started."
        )
    print(f"AWS identity verified: account {account_id}; principal {arn}")
    return session


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
            "apigateway", "ecs", "cloudfront", "waf", "elb", "securityhub", "guardduty", "config", "macie", "eks", "cloudwatch", "codebuild",
        ],
        help="Limit AWS discovery to selected service domains; repeat to select multiple. Default: all supported domains.",
    )

    parser.add_argument(
        "--include-native-findings",
        action="store_true",
        help="Import bounded native Security Hub, GuardDuty, IAM Access Analyzer, Amazon Inspector and Macie findings (AWS source only).",
    )
    parser.add_argument(
        "--native-findings-limit",
        type=int,
        default=100,
        help="Maximum findings to import per native source (1-1000; default: 100).",
    )

    parser.add_argument(
        "--securityhub-workflow-status",
        action="append",
        choices=["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"],
        help="Filter imported Security Hub findings by workflow status; repeat to include multiple statuses.",
    )
    parser.add_argument(
        "--securityhub-record-state",
        choices=["ACTIVE", "ARCHIVED", "ALL"],
        default="ACTIVE",
        help="Security Hub finding record state to import (default: ACTIVE; ALL disables this filter).",
    )
    parser.add_argument(
        "--securityhub-compliance-status",
        choices=["PASSED", "WARNING", "FAILED", "NOT_AVAILABLE", "NOT_SUPPORTED"],
        help="Optional Security Hub control compliance-status filter.",
    )

    parser.add_argument(
        "--guardduty-region",
        action="append",
        help="Region to query for native GuardDuty findings; repeat to scan multiple regions. Defaults to --region or the configured AWS region.",
    )
    parser.add_argument(
        "--guardduty-record-state",
        choices=["ACTIVE", "ARCHIVED", "ALL"],
        default="ALL",
        help="Filter native GuardDuty findings by archived state (default: ALL, preserving existing behaviour).",
    )
    parser.add_argument(
        "--guardduty-updated-after",
        help="Optional ISO-8601 date-time lower bound for GuardDuty finding updates, e.g. 2026-10-01T00:00:00Z.",
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
        "--summary-output",
        type=Path,
        help="Optional path for a separate versioned machine-readable scan summary JSON.",
    )
    parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        default=None,
        help="Exit with code 3 when any reported finding meets or exceeds this severity.",
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

    parser.add_argument(
        "--risk-score",
        action="store_true",
        help="Add optional versioned risk scores and factor explanations to each finding.",
    )
    parser.add_argument(
        "--risk-config",
        type=Path,
        help="Optional JSON risk-scoring configuration (requires --risk-score).",
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
    discovery_coverage: list[dict] | None = None,
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
            "s3": [provider.discover_s3_buckets, provider.discover_s3_account_public_access_block],
            "iam": [provider.discover_iam_policies, provider.discover_iam_roles, provider.discover_iam_users, provider.discover_iam_account],
            "ec2": [provider.discover_ec2_instances],
            "ebs": [provider.discover_ebs_volumes, provider.discover_ebs_snapshots, provider.discover_amis],
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
            "apigateway": [provider.discover_api_gateway_rest_apis, provider.discover_api_gateway_http_apis],
            "ecs": [provider.discover_ecs_task_definitions, provider.discover_ecs_services],
            "cloudfront": [provider.discover_cloudfront_distributions],
            "waf": [lambda: provider.discover_waf_web_acls("CLOUDFRONT"), lambda: provider.discover_waf_web_acls("REGIONAL")],
            "elb": [provider.discover_application_load_balancers],
            "securityhub": [provider.discover_security_hub],
            "guardduty": [provider.discover_guardduty],
            "config": [provider.discover_aws_config],
            "macie": [provider.discover_macie_session],
            "eks": [provider.discover_eks_clusters],
            "cloudwatch": [provider.discover_cloudwatch_log_groups, provider.discover_cloudwatch_alarms],
            "codebuild": [provider.discover_codebuild_projects],
        }
        selected_services = list(dict.fromkeys(services)) if services else list(discovery_by_service)
        resources = []
        for service in selected_services:
            service_resources = []
            successful_operations = 0
            failed_operations = []
            for discover in discovery_by_service[service]:
                try:
                    discovered = discover()
                except (ClientError, BotoCoreError, RuntimeError) as exc:
                    if isinstance(exc, ClientError):
                        error_code = exc.response.get("Error", {}).get("Code", "ClientError")
                    else:
                        error_code = type(exc).__name__
                    operation_name = (
                        getattr(discover, "_mock_name", None)
                        or getattr(discover, "__name__", None)
                        or "discovery"
                    )
                    failed_operations.append({
                        "operation": str(operation_name)[:120],
                        "error_code": str(error_code)[:80],
                    })
                    continue
                successful_operations += 1
                service_resources.extend(discovered)

            resources.extend(service_resources)
            if discovery_coverage is not None:
                if failed_operations and successful_operations:
                    status = "partial"
                elif failed_operations:
                    status = "failed"
                elif not service_resources:
                    status = "empty"
                else:
                    status = "success"
                discovery_coverage.append({
                    "service": service,
                    "status": status,
                    "resources_discovered": len(service_resources),
                    "successful_operations": successful_operations,
                    "failed_operations": failed_operations,
                })

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
    return_coverage: bool = False,
    securityhub_workflow_status: list[str] | None = None,
    securityhub_record_state: str = "ACTIVE",
    securityhub_compliance_status: str | None = None,
    guardduty_regions: list[str] | None = None,
    guardduty_record_state: str = "ALL",
    guardduty_updated_after: str | None = None,
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
            "apigateway", "ecs", "cloudfront", "waf", "elb", "securityhub", "guardduty", "config", "macie", "eks",
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
    discovery_coverage: list[dict] = []
    if aws_session is None and expected_account_id is None and services is None and not return_coverage:
        resources = discover_resources(source, source_path, region)
    else:
        resources = discover_resources(
            source,
            source_path,
            region,
            aws_session,
            expected_account_id,
            services,
            discovery_coverage if return_coverage else None,
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
    if source == "terraform":
        for resource in resources:
            unknown = resource.attributes.get("terraform_unknown_attributes", [])
            if unknown:
                findings.append(
                    Finding(
                        check_id="IAC-TF-PLAN-001",
                        severity=Severity.INFO,
                        service="Terraform plan",
                        resource=resource.attributes.get("terraform_address", resource.resource_id),
                        title="Terraform plan contains unknown values",
                        description="One or more planned resource attributes are unknown at plan time. Checks that depend on those attributes cannot establish the final security posture.",
                        remediation="Review the plan after resolving its inputs, or provide a later reviewed plan where these attributes are known.",
                        region=resource.region,
                        evidence="unknown_attributes=" + ", ".join(str(item) for item in unknown[:20]),
                    )
                )
            if resource.attributes.get("terraform_removed") is True:
                findings.append(
                    Finding(
                        check_id="IAC-TF-PLAN-002",
                        severity=Severity.INFO,
                        service="Terraform plan",
                        resource=resource.attributes.get("terraform_address", resource.resource_id),
                        title="Terraform plan removes a resource",
                        description="This resource is planned for deletion and was excluded from current-posture rule evaluation.",
                        remediation="Review the planned deletion and its downstream dependencies as part of change approval.",
                        region=resource.region,
                        evidence="terraform_plan_actions=" + ", ".join(resource.attributes.get("terraform_plan_actions", ["delete"])),
                    )
                )
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
        try:
            native_items = native_provider.get_securityhub_findings(
                limit=native_findings_limit,
                workflow_statuses=securityhub_workflow_status,
                record_state=None if securityhub_record_state == "ALL" else securityhub_record_state,
                compliance_status=securityhub_compliance_status,
            )
            if return_coverage:
                discovery_coverage.append({
                    "service": "securityhub-findings",
                    "status": "success" if native_items else "empty",
                    "resources_discovered": len(native_items),
                    "successful_operations": 1,
                    "failed_operations": [],
                    "bounded_limit": native_findings_limit,
                })
        except (ClientError, BotoCoreError, RuntimeError) as exc:
            if not return_coverage:
                raise
            error_code = (
                exc.response.get("Error", {}).get("Code", "ClientError")
                if isinstance(exc, ClientError) else type(exc).__name__
            )
            if return_coverage:
                discovery_coverage.append({
                    "service": "securityhub-findings",
                    "status": "failed",
                    "resources_discovered": 0,
                    "successful_operations": 0,
                    "failed_operations": [{"operation": "get_findings", "error_code": str(error_code)[:80]}],
                })
            native_items = []
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

        configured_region = (
            region
            or getattr(aws_session, "region_name", None)
            or boto3.Session().region_name
            or "us-east-1"
        )
        selected_guardduty_regions = list(dict.fromkeys(guardduty_regions or [configured_region]))
        if any(not isinstance(item, str) or not item.strip() for item in selected_guardduty_regions):
            raise ValueError("GuardDuty regions must be non-empty region names.")
        seen_guardduty_findings: set[tuple[str, str | None, str]] = set()
        for guardduty_region in selected_guardduty_regions:
            regional_provider = (
                AWSProvider(region=guardduty_region, session=aws_session)
                if aws_session is not None
                else AWSProvider(region=guardduty_region)
            )
            archived_filter = (
                None if guardduty_record_state == "ALL"
                else guardduty_record_state == "ARCHIVED"
            )
            try:
                guardduty_items = regional_provider.get_guardduty_findings(
                    limit=native_findings_limit,
                    archived=archived_filter,
                    updated_after=guardduty_updated_after,
                    require_detector=True,
                )
                if return_coverage:
                    discovery_coverage.append({
                        "service": f"guardduty-findings:{guardduty_region}",
                        "status": "success" if guardduty_items else "empty",
                        "resources_discovered": len(guardduty_items),
                        "successful_operations": 1,
                        "failed_operations": [],
                        "bounded_limit": native_findings_limit,
                    })
            except (ClientError, BotoCoreError, RuntimeError) as exc:
                if not return_coverage:
                    raise
                error_code = (
                    exc.response.get("Error", {}).get("Code", "ClientError")
                    if isinstance(exc, ClientError) else
                    "GuardDutyNotEnabled" if "not enabled" in str(exc).lower() or "no detector" in str(exc).lower()
                    else type(exc).__name__
                )
                discovery_coverage.append({
                    "service": f"guardduty-findings:{guardduty_region}",
                    "status": "failed",
                    "resources_discovered": 0,
                    "successful_operations": 0,
                    "failed_operations": [{"operation": "get_findings", "error_code": str(error_code)[:80]}],
                })
                continue
            for item in guardduty_items:
                converted = guardduty_to_finding(item, fallback_region=guardduty_region)
                if converted is None:
                    continue
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                identity = (
                    converted.region or guardduty_region,
                    converted.account_id,
                    converted.source_id or "",
                )
                if identity in seen_guardduty_findings:
                    continue
                seen_guardduty_findings.add(identity)
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

        inspector_items = native_provider.get_inspector_findings(
            limit=native_findings_limit
        )
        for item in inspector_items:
            converted = inspector_to_finding(item, fallback_region=region)
            if converted is not None:
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                findings.append(converted)

        macie_items = native_provider.get_macie_findings(
            limit=native_findings_limit
        )
        for item in macie_items:
            converted = macie_to_finding(item, fallback_region=region)
            if converted is not None:
                if converted.account_id is None:
                    converted.account_id = expected_account_id
                findings.append(converted)

    if return_resources and return_coverage:
        return findings, resources, discovery_coverage
    if return_resources:
        return findings, resources
    if return_coverage:
        return findings, discovery_coverage
    return findings


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

    started_at = perf_counter()
    if args.summary_output:
        default_report_path = Path(
            "reports/scan.html"
            if args.format == "html"
            else "reports/scan.sarif"
            if args.format == "sarif"
            else "reports/scan.json"
        )
        selected_report_path = args.output or default_report_path
        if args.summary_output.resolve() == selected_report_path.resolve():
            parser.error("--summary-output must not overwrite the detailed --output report")

    if args.diff_output and not args.compare_baseline:
        parser.error("--diff-output requires --compare-baseline")
    if args.risk_config and not args.risk_score:
        parser.error("--risk-config requires --risk-score")
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
    if (
        (args.securityhub_workflow_status or args.securityhub_record_state != "ACTIVE"
         or args.securityhub_compliance_status is not None)
        and not args.include_native_findings
    ):
        parser.error("Security Hub filters require --include-native-findings")
    if (
        (args.guardduty_region or args.guardduty_record_state != "ALL"
         or args.guardduty_updated_after is not None)
        and not args.include_native_findings
    ):
        parser.error("GuardDuty filters require --include-native-findings")

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

    risk_config = None
    if args.risk_score:
        registered_check_ids = {rule.metadata.check_id for rule in get_all_rules()}
        try:
            risk_config = load_risk_config(args.risk_config, registered_check_ids)
        except RiskScoringConfigError as exc:
            parser.error(str(exc))

    assessment_metadata = None
    discovery_coverage = None
    graph_resources = None
    live_aws_session = None
    if args.source == "aws" and not args.accounts_file:
        try:
            live_aws_session = create_verified_aws_session(args.profile, args.region)
        except RuntimeError as exc:
            parser.error(str(exc))
    if args.accounts_file:
        findings, assessment_metadata = run_multi_account_scan(
            args.accounts_file,
            region=args.region,
            scan_function=run_scan,
            policy_path=args.policy,
            include_native_findings=args.include_native_findings,
            native_findings_limit=args.native_findings_limit,
            guardduty_regions=args.guardduty_region,
            guardduty_record_state=args.guardduty_record_state,
            guardduty_updated_after=args.guardduty_updated_after,
        )
    else:
        scan_result = run_scan(
            args.source,
            args.file,
            args.policy,
            args.region,
            args.include_native_findings,
            args.native_findings_limit,
            profile=None if live_aws_session is not None else args.profile,
            aws_session=live_aws_session,
            services=args.service,
            return_resources=bool(args.graph_output),
            return_coverage=(args.source == "aws"),
            securityhub_workflow_status=args.securityhub_workflow_status,
            securityhub_record_state=args.securityhub_record_state,
            securityhub_compliance_status=args.securityhub_compliance_status,
            guardduty_regions=args.guardduty_region,
            guardduty_record_state=args.guardduty_record_state,
            guardduty_updated_after=args.guardduty_updated_after,
        )
        if args.graph_output and args.source == "aws":
            findings, graph_resources, discovery_coverage = scan_result
        elif args.graph_output:
            findings, graph_resources = scan_result
        elif args.source == "aws":
            findings, discovery_coverage = scan_result
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
    if args.risk_score:
        findings = score_findings(findings, risk_config)

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
        report_assessment = assessment_metadata
        if discovery_coverage is not None:
            failed_services = sum(
                item["status"] in {"partial", "failed"}
                for item in discovery_coverage
            )
            report_assessment = {
                "discovery_coverage": discovery_coverage,
                "discovery_summary": {
                    "services_assessed": len(discovery_coverage),
                    "services_with_gaps": failed_services,
                },
            }
        write_json_report(findings, output_path, compliance_mapping, report_assessment)
    elif args.format == "html":
        write_html_report(findings, output_path, compliance_mapping, assessment_metadata)
    else:
        write_sarif_report(findings, output_path, compliance_mapping, assessment_metadata)

    print(
        f"Security scan complete. "
        f"{len(findings)} findings written to {output_path}"
    )
    discovery_has_gaps = False
    if discovery_coverage is not None:
        discovery_has_gaps = any(
            item["status"] in {"partial", "failed"}
            for item in discovery_coverage
        )
        for item in discovery_coverage:
            print(
                f"Discovery {item['service']}: {item['status']} "
                f"({item['resources_discovered']} resources)"
            )
        if discovery_has_gaps:
            print(
                "Warning: one or more service domains were only partially assessed "
                "or failed. Review discovery coverage in the JSON report before "
                "treating this scan as complete."
            )
    threshold_met = threshold_is_met(findings, args.fail_on)
    if args.summary_output:
        summary = build_scan_summary(
            findings,
            source=args.source,
            region=args.region,
            services=args.service,
            report_format=args.format,
            report_path=output_path,
            duration_seconds=perf_counter() - started_at,
            discovery_coverage=discovery_coverage,
            assessment_metadata=assessment_metadata,
            fail_on=args.fail_on,
            threshold_met=threshold_met,
        )
        write_scan_summary(summary, args.summary_output)
        print(f"Machine-readable scan summary written to {args.summary_output}")

    assessment_incomplete = bool(
        baseline_actions_skipped
        or (assessment_metadata and assessment_metadata["summary"]["failed_accounts"] > 0)
        or discovery_has_gaps
    )
    exit_code = scan_exit_code(incomplete=assessment_incomplete, threshold_met=threshold_met)
    if exit_code:
        raise SystemExit(exit_code)


if __name__ == "__main__":
    main()