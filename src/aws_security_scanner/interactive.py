"""Question-driven setup for the command-line scanner.

The wizard only collects options. It never creates AWS credentials or changes
cloud configuration; AWS authentication remains delegated to boto3.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path


AWS_SERVICES = (
    "s3", "iam", "ec2", "ebs", "vpc", "cloudtrail", "kms", "rds",
    "lambda", "secretsmanager", "ecr", "dynamodb", "sqs", "sns",
    "apigateway", "ecs", "cloudfront", "waf", "elb", "securityhub",
    "guardduty", "config", "macie", "eks", "cloudwatch", "efs", "codebuild",
)
QUICK_SERVICES = ("s3", "iam", "ec2", "vpc", "cloudtrail", "kms", "ebs")
SOURCES = ("fixture", "terraform", "hcl", "snapshot", "aws")
FORMATS = ("html", "json", "sarif", "ocsf")
SEVERITIES = ("", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _choose(
    prompt: str,
    options: tuple[str, ...],
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
    *,
    default: str | None = None,
) -> str:
    """Prompt until a valid numbered choice is entered."""
    while True:
        output_fn(prompt)
        for index, option in enumerate(options, start=1):
            suffix = " (default)" if option == default else ""
            output_fn(f"  {index}. {option}{suffix}")
        answer = input_fn("Choose a number (or q to cancel): ").strip().lower()
        if answer == "q":
            raise KeyboardInterrupt
        if not answer and default is not None:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        output_fn("Invalid selection. Enter one of the listed numbers, or q to cancel.")


def _ask(prompt: str, input_fn: Callable[[str], str], *, default: str = "") -> str:
    answer = input_fn(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return answer or default


def _expand_path(value: str) -> str:
    """Expand a user-home prefix in a path entered at an interactive prompt."""
    return str(Path(value).expanduser()) if value else value


def _yes_no(
    prompt: str,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
    *,
    default: bool = False,
) -> bool:
    marker = "Y/n" if default else "y/N"
    while True:
        answer = input_fn(f"{prompt} ({marker}): ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        output_fn("Please answer y or n.")


def build_interactive_args(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> list[str] | None:
    """Collect scan options and return CLI arguments, or None on cancellation.

    All functions are injectable so the wizard can be tested without a TTY.
    """
    try:
        output_fn("\nAWS Security Scanner — guided scan setup")
        output_fn("Choose a source. AWS scans use your configured boto3 credentials/profile;")
        output_fn("the scanner never asks for access keys or secret keys.")
        source = _choose(
            "Where should the scanner read configuration from?",
            ("fixture", "terraform JSON (.json)", "Terraform HCL (.tf)", "resource snapshot (.json)", "live AWS account"),
            input_fn,
            output_fn,
            default="terraform JSON (.json)",
        )
        source = {
            "terraform JSON (.json)": "terraform",
            "Terraform HCL (.tf)": "hcl",
            "resource snapshot (.json)": "snapshot",
            "live AWS account": "aws",
        }.get(source, source)
        args = ["--source", source]

        if source in {"fixture", "terraform", "hcl", "snapshot"}:
            label = {
                "fixture": "Fixture file or directory path",
                "terraform": "Terraform JSON file path",
                "hcl": "Terraform HCL (.tf) file path",
                "snapshot": "Resource snapshot JSON file path",
            }[source]
            while True:
                entered_path = _ask(label, input_fn)
                if not entered_path:
                    output_fn("A source path is required.")
                    continue
                path = Path(_expand_path(entered_path))
                if not path.exists():
                    output_fn(f"Path does not exist: {path}. Check the path and try again.")
                    continue
                if source == "terraform" and path.suffix.lower() in {".tf", ".tfvars"}:
                    source = "hcl"
                    args[1] = source
                    output_fn("Detected a Terraform HCL file; switching the source to hcl.")
                elif source == "hcl" and path.suffix.lower() == ".json":
                    source = "terraform"
                    args[1] = source
                    output_fn("Detected a Terraform JSON file; switching the source to terraform.")
                args.extend(["--file", str(path)])
                break
            output_fn("File-based scans run all checks applicable to the supplied resources.")
        else:
            depth = _choose(
                "How broad should the AWS scan be?",
                ("Quick — core services", "Standard — all supported services", "Comprehensive — all services and native findings", "Custom — choose services"),
                input_fn,
                output_fn,
                default="Standard — all supported services",
            )
            if depth.startswith("Quick"):
                services = list(QUICK_SERVICES)
            elif depth.startswith("Standard"):
                services = list(AWS_SERVICES)
            elif depth.startswith("Comprehensive"):
                services = list(AWS_SERVICES)
                args.append("--include-native-findings")
            else:
                services = []
                output_fn("Supported services: " + ", ".join(AWS_SERVICES))
                while not services:
                    selected = _ask("Enter comma-separated service names", input_fn)
                    candidate = list(dict.fromkeys(item.strip().lower() for item in selected.split(",") if item.strip()))
                    unknown = sorted(set(candidate) - set(AWS_SERVICES))
                    if unknown:
                        output_fn("Unknown service(s): " + ", ".join(unknown))
                    elif candidate:
                        services = candidate
                    else:
                        output_fn("Choose at least one service.")
                if _yes_no("Include bounded native Security Hub and GuardDuty findings?", input_fn, output_fn):
                    args.append("--include-native-findings")
            for service in services:
                args.extend(["--service", service])

            region = _ask("AWS region (blank uses your AWS SDK configuration)", input_fn)
            if region:
                args.extend(["--region", region])

            multi_account = _yes_no("Use an explicit multi-account target file?", input_fn, output_fn)
            if multi_account:
                while True:
                    accounts_path = _expand_path(_ask("Path to accounts JSON file", input_fn))
                    if accounts_path:
                        args.extend(["--accounts-file", accounts_path])
                        break
                    output_fn("An accounts file path is required.")
            else:
                profile = _ask("AWS shared-config profile name (blank uses the default credential chain)", input_fn)
                if profile:
                    args.extend(["--profile", profile])

        report_format = _choose(
            "Which report format do you want?",
            FORMATS,
            input_fn,
            output_fn,
            default="html",
        )
        args.extend(["--format", report_format])
        output = _expand_path(_ask("Report output path", input_fn, default=f"reports/scan.{report_format}"))
        args.extend(["--output", output])

        severity = _choose(
            "Minimum finding severity to include?",
            ("No severity filter", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
            input_fn,
            output_fn,
            default="No severity filter",
        )
        if severity != "No severity filter":
            args.extend(["--min-severity", severity])

        if _yes_no("Include optional risk scores and factor explanations?", input_fn, output_fn):
            args.append("--risk-score")
            risk_config = _expand_path(_ask("Optional risk-scoring JSON path (blank for defaults)", input_fn))
            if risk_config:
                args.extend(["--risk-config", risk_config])

        policy = _expand_path(_ask("Optional YAML policy path (blank for defaults)", input_fn))
        if policy:
            args.extend(["--policy", policy])
        mapping = _expand_path(_ask("Optional compliance mapping JSON path (blank to skip)", input_fn))
        if mapping:
            args.extend(["--compliance-mapping", mapping])

        if not any(option == "--accounts-file" for option in args):
            graph_path = _expand_path(_ask("Optional resource graph JSON path (blank to skip)", input_fn))
            if graph_path:
                args.extend(["--graph-output", graph_path])

        baseline_action = _choose(
            "Baseline operation",
            ("None", "Suppress findings matching a baseline", "Write a new baseline", "Compare against a baseline"),
            input_fn,
            output_fn,
            default="None",
        )
        if baseline_action != "None":
            path = _expand_path(_ask("Baseline JSON path", input_fn))
            if not path:
                output_fn("Baseline operation cancelled because no path was supplied.")
                raise KeyboardInterrupt
            option = {
                "Suppress findings matching a baseline": "--baseline",
                "Write a new baseline": "--write-baseline",
                "Compare against a baseline": "--compare-baseline",
            }[baseline_action]
            args.extend([option, path])
            if option == "--compare-baseline":
                diff_path = _expand_path(_ask("Diff JSON output path", input_fn, default="reports/baseline-diff.json"))
                args.extend(["--diff-output", diff_path])

        output_fn("\nReview your scan configuration:")
        for index, argument in enumerate(args):
            if argument.startswith("--"):
                if index + 1 < len(args) and not args[index + 1].startswith("--"):
                    output_fn(f"  {argument}: {args[index + 1]}")
                else:
                    output_fn(f"  {argument}: enabled")
        if not _yes_no("Start this scan now?", input_fn, output_fn, default=False):
            output_fn("Scan cancelled; no scan was started.")
            return None
        return args
    except KeyboardInterrupt:
        output_fn("\nScan setup cancelled; no scan was started.")
        return None
