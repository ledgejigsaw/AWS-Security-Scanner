import argparse
from pathlib import Path

from aws_security_scanner.engine import RuleEngine
from aws_security_scanner.normalization.terraform import aggregate_s3_resources
from aws_security_scanner.providers.fixture import FixtureProvider
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.reporting.json_reporter import write_json_report
from aws_security_scanner.rules.registry import get_all_rules
from aws_security_scanner.policy import SecurityPolicy



def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="AWS cloud security posture assessment tool."
    )

    parser.add_argument(
        "--source",
        choices=["fixture", "terraform"],
        required=True,
        help="Security resource source.",
    )

    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="Fixture directory or Terraform JSON file.",
    )

    parser.add_argument(
        "--format",
        choices=["json"],
        default="json",
        help="Report output format.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/scan.json"),
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
    source_path: Path,
):
    """Discover resources from the selected source."""

    if source == "fixture":
        provider = FixtureProvider(source_path)
        return provider.discover()

    if source == "terraform":
        provider = TerraformProvider(source_path)
        resources = provider.discover()

        return aggregate_s3_resources(resources)

    raise ValueError(f"Unsupported source: {source}")


def run_scan(
    source: str,
    source_path: Path,
    policy_path: Path | None = None,
) -> list:
    resources = discover_resources(source, source_path)

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
    )

    if args.format == "json":
        write_json_report(
            findings,
            args.output,
        )

        print(
            f"Security scan complete. "
            f"{len(findings)} findings written to {args.output}"
        )


if __name__ == "__main__":
    main()