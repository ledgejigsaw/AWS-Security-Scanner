from aws_security_scanner.cli import build_parser
from aws_security_scanner.interactive import build_interactive_args


class Answers:
    def __init__(self, answers):
        self.answers = iter(answers)

    def __call__(self, _prompt):
        return next(self.answers)


def test_parser_accepts_interactive_mode_without_source():
    args = build_parser().parse_args(["--interactive"])

    assert args.interactive is True
    assert args.source is None


def test_interactive_file_scan_builds_cli_arguments_and_confirms():
    answers = Answers([
        "1",                         # fixture source
        "tests/fixtures",            # source path
        "2",                         # JSON report
        "reports/custom.json",       # output path
        "3",                         # HIGH minimum severity
        "n",                         # no risk score
        "policies/default.yaml",     # policy
        "",                          # no compliance mapping
        "",                          # no graph
        "1",                         # no baseline operation
        "yes",                       # confirm
    ])
    output = []

    args = build_interactive_args(answers, output.append)

    assert args is not None
    assert args[:4] == ["--source", "fixture", "--file", "tests/fixtures"]
    assert "--format" in args and args[args.index("--format") + 1] == "json"
    assert "--output" in args and args[args.index("--output") + 1] == "reports/custom.json"
    assert "--min-severity" in args and args[args.index("--min-severity") + 1] == "HIGH"
    assert "--policy" in args
    assert any("Review your scan configuration" in line for line in output)


def test_interactive_quick_aws_scan_selects_only_core_services():
    answers = Answers([
        "4",       # AWS source
        "1",       # quick depth
        "eu-west-2",
        "n",       # no multi-account
        "security-audit",
        "3",       # SARIF
        "reports/aws.sarif",
        "1",       # no severity filter
        "n",       # no risk score
        "",        # policy
        "",        # compliance mapping
        "",        # graph
        "1",       # no baseline
        "y",       # confirm
    ])

    args = build_interactive_args(answers, lambda _message: None)

    assert args is not None
    assert args.count("--service") == 7
    assert args[args.index("--service") + 1] == "s3"
    assert "--include-native-findings" not in args
    assert args[args.index("--profile") + 1] == "security-audit"
    assert args[args.index("--format") + 1] == "sarif"


def test_interactive_cancellation_does_not_return_scan_arguments():
    answers = Answers([
        "1", "tests/fixtures", "1", "", "1", "n", "", "", "", "1", "n"
    ])
    output = []

    args = build_interactive_args(answers, output.append)

    assert args is None
    assert any("Scan cancelled" in line for line in output)


def test_interactive_invalid_custom_service_reprompts():
    answers = Answers([
        "4",                         # AWS
        "4",                         # custom services
        "made-up-service",           # invalid
        "s3,iam",                    # valid
        "n",                         # no native findings
        "",                          # region
        "n",                         # no multi-account
        "",                          # default profile
        "2",                         # JSON
        "",                          # output default
        "1",                         # no severity filter
        "n",                         # no risk score
        "",                          # policy
        "",                          # mapping
        "",                          # graph
        "1",                         # no baseline
        "y",                         # confirm
    ])
    output = []

    args = build_interactive_args(answers, output.append)

    assert args is not None
    assert args.count("--service") == 2
    assert "Unknown service(s): made-up-service" in output



def test_interactive_setup_can_enable_risk_scores_with_configuration():
    answers = Answers([
        "1", "tests/fixtures", "2", "", "1",
        "y", "risk.json", "", "", "", "1", "y",
    ])

    args = build_interactive_args(answers, lambda _message: None)

    assert args is not None
    assert "--risk-score" in args
    assert args[args.index("--risk-config") + 1] == "risk.json"



def test_interactive_supported_service_set_includes_macie():
    from aws_security_scanner.interactive import AWS_SERVICES

    assert "macie" in AWS_SERVICES
