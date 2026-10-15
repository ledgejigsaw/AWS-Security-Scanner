from pathlib import Path

from aws_security_scanner.interactive import build_interactive_args


def _answers(source_choice: str, source_path: str, output_path: str = "") -> list[str]:
    return [
        source_choice,
        source_path,
        "2",  # JSON report
        output_path,
        "",  # no severity filter
        "n",  # no risk scoring
        "",  # no policy
        "",  # no compliance mapping
        "",  # no resource graph
        "",  # no baseline operation
        "y",  # confirm scan
    ]


def _run_wizard(monkeypatch, answers: list[str], home: Path):
    monkeypatch.setenv("HOME", str(home))
    iterator = iter(answers)
    output: list[str] = []
    result = build_interactive_args(
        input_fn=lambda _prompt: next(iterator),
        output_fn=output.append,
    )
    return result, output


def test_interactive_expands_home_and_detects_hcl_file(monkeypatch, tmp_path):
    terraform_file = tmp_path / "terraform-secure.tf"
    terraform_file.write_text('resource "aws_s3_bucket" "example" {}\n')
    output_path = tmp_path / "reports" / "scan.json"

    result, output = _run_wizard(
        monkeypatch,
        _answers("2", "~/terraform-secure.tf", "~/reports/scan.json"),
        tmp_path,
    )

    assert result is not None
    assert result[result.index("--source") + 1] == "hcl"
    assert result[result.index("--file") + 1] == str(terraform_file)
    assert result[result.index("--output") + 1] == str(output_path)
    assert any("switching the source to hcl" in line for line in output)


def test_interactive_detects_terraform_json_when_hcl_was_selected(monkeypatch, tmp_path):
    terraform_file = tmp_path / "terraform.json"
    terraform_file.write_text('{"resource": {}}\n')

    result, output = _run_wizard(
        monkeypatch,
        _answers("3", str(terraform_file)),
        tmp_path,
    )

    assert result is not None
    assert result[result.index("--source") + 1] == "terraform"
    assert result[result.index("--file") + 1] == str(terraform_file)
    assert any("switching the source to terraform" in line for line in output)


def test_interactive_reprompts_when_source_path_does_not_exist(monkeypatch, tmp_path):
    terraform_file = tmp_path / "terraform-secure.tf"
    terraform_file.write_text('resource "aws_s3_bucket" "example" {}\n')
    answers = _answers("2", "~/missing.tf")
    answers.insert(2, "~/terraform-secure.tf")

    result, output = _run_wizard(monkeypatch, answers, tmp_path)

    assert result is not None
    assert result[result.index("--source") + 1] == "hcl"
    assert result[result.index("--file") + 1] == str(terraform_file)
    assert any("Path does not exist" in line for line in output)
