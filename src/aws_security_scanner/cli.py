import argparse
import json
from pathlib import Path

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.providers.aws import AWSProvider
from aws_security_scanner.integrations.securityhub import securityhub_to_finding
from aws_security_scanner.multi_account import run_multi_account_scan
from aws_security_scanner.reporting.json_reporter import write_json_report
from aws_security_scanner.reporting.html_reporter import write_html_report
from aws_security_scanner.reporting.sarif_reporter import write_sarif_report
from aws_security_scanner.rules.registry import get_all_rules
from aws_security_scanner.policy import SecurityPolicy
from aws_security_scanner.models.finding import Severity
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
        "--source",
        choices=["fixture", "terraform", "aws"],
        required=True,
        help="Security resource source.",
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Fixture directory or Terraform JSON file.",
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
        "--include-native-findings",
        action="store_true",
        help="Import a bounded set of native AWS Security Hub findings (AWS source only).",
    )
    parser.add_argument(
        "--native-findings-limit",
        type=int,
        default=100,
        help="Maximum number of Security Hub findings to import (1-1000; default: 100).",
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

    if source == "aws":
        provider = AWSProvider(region=region, session=aws_session)

        resources = []

        resources.extend(
            provider.discover_s3_buckets()
        )

        resources.extend(
            provider.discover_iam_policies()
        )

        resources.extend(
            provider.discover_iam_roles()
        )

        resources.extend(
            provider.discover_iam_users()
        )

        resources.extend(
            provider.discover_iam_account()
        )
        resources.extend(
            provider.discover_ec2_instances()
        )

        resources.extend(
            provider.discover_ebs_volumes()
        )

        resources.extend(
            provider.discover_ebs_snapshots()
        )

        resources.extend(
            provider.discover_security_groups()
        )

        resources.extend(
            provider.discover_waf_web_acls("CLOUDFRONT")
        )

        resources.extend(
            provider.discover_waf_web_acls("REGIONAL")
        )

        resources.extend(
            provider.discover_application_load_balancers()
        )

        resources.extend(
            provider.discover_security_hub()
        )

        resources.extend(
            provider.discover_guardduty()
        )

        resources.extend(
            provider.discover_vpcs()
        )

        resources.extend(
            provider.discover_subnets()
        )

        resources.extend(
            provider.discover_route_tables()
        )

        resources.extend(
            provider.discover_network_acls()
        )

        resources.extend(
            provider.discover_flow_logs()
        )

        resources.extend(
            provider.discover_cloudtrail_trails()
        )

        resources.extend(
            provider.discover_kms_keys()
        )

        resources.extend(
            provider.discover_rds_instances()
        )

        resources.extend(
            provider.discover_lambda_functions()
        )

        resources.extend(
            provider.discover_secrets_manager_secrets()
        )

        resources.extend(
            provider.discover_ecr_repositories()
        )

        resources.extend(
            provider.discover_dynamodb_tables()
        )

        resources.extend(
            provider.discover_sqs_queues()
        )

        resources.extend(
            provider.discover_sns_topics()
        )

        resources.extend(
            provider.discover_api_gateway_rest_apis()
        )

        resources.extend(
            provider.discover_ecs_task_definitions()
        )

        resources.extend(
            provider.discover_ecs_services()
        )

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
) -> list:
    if include_native_findings and source != "aws":
        raise ValueError("--include-native-findings can only be used with --source aws.")
    if include_native_findings and (
        isinstance(native_findings_limit, bool)
        or not isinstance(native_findings_limit, int)
        or not 1 <= native_findings_limit <= 1000
    ):
        raise ValueError("--native-findings-limit must be between 1 and 1000.")

    resources = discover_resources(
        source,
        source_path,
        region,
        aws_session,
        expected_account_id,
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

    if include_native_findings:
        # Keep native finding ingestion opt-in. A separate provider instance
        # avoids changing the existing discovery call contract for normal scans.
        native_provider = AWSProvider(region=region, session=aws_session)
        native_items = native_provider.get_securityhub_findings(limit=native_findings_limit)
        findings.extend(
            converted
            for item in native_items
            if (converted := securityhub_to_finding(item, fallback_region=region)) is not None
        )

    return findings


def main() -> None:
    """Run the AWS Security Scanner CLI."""

    parser = build_parser()
    args = parser.parse_args()

    if args.diff_output and not args.compare_baseline:
        parser.error("--diff-output requires --compare-baseline")
    if args.include_native_findings and args.source != "aws":
        parser.error("--include-native-findings can only be used with --source aws")
    if args.accounts_file and args.source != "aws":
        parser.error("--accounts-file can only be used with --source aws")
    if args.accounts_file and args.file:
        parser.error("--accounts-file cannot be combined with --file")
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
        findings = run_scan(
            args.source,
            args.file,
            args.policy,
            args.region,
            args.include_native_findings,
            args.native_findings_limit,
        )

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


if __name__ == "__main__":
    main()