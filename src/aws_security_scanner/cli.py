import argparse
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

    findings = run_scan(
        args.source,
        args.file,
        args.policy,
        args.region
    )

    if args.write_baseline:
        write_baseline(findings, args.write_baseline)

    if args.baseline:
        findings = exclude_baselined_findings(
            findings,
            load_baseline(args.baseline),
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