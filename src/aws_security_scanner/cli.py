import argparse
import json
from pathlib import Path

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.providers.aws import AWSProvider
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
        "--region",
        help="AWS region to scan.",
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
        provider = AWSProvider(region=region)

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
            provider.discover_security_groups()
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

        resources.extend(
            provider.discover_cloudfront_distributions()
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

        return resources


def run_scan(
    source: str,
    source_path: Path | None = None,
    policy_path: Path | None = None,
    region: str | None = None,
) -> list:
    resources = discover_resources(
        source,
        source_path,
        region,
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

    return engine.scan(resources)


def main() -> None:
    """Run the AWS Security Scanner CLI."""

    parser = build_parser()
    args = parser.parse_args()

    if args.diff_output and not args.compare_baseline:
        parser.error("--diff-output requires --compare-baseline")

    findings = run_scan(
        args.source,
        args.file,
        args.policy,
        args.region
    )

    if args.write_baseline:
        write_history_baseline(findings, args.write_baseline)

    if args.compare_baseline:
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

    if args.baseline:
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
        write_json_report(findings, output_path)
    elif args.format == "html":
        write_html_report(findings, output_path)
    else:
        write_sarif_report(findings, output_path)

    print(
        f"Security scan complete. "
        f"{len(findings)} findings written to {output_path}"
    )


if __name__ == "__main__":
    main()