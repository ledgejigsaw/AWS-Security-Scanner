import html
from pathlib import Path

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.reporting.summary import build_summary


def build_html_report(findings: list[Finding]) -> str:
    """Build a self-contained HTML report with escaped finding content."""
    summary = build_summary(findings)
    rows = []

    for finding in findings:
        values = (
            finding.severity.value,
            finding.check_id,
            finding.service,
            finding.resource,
            finding.title,
            finding.description,
            finding.remediation,
            finding.region or "",
            finding.evidence or "",
        )
        cells = "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in values
        )
        rows.append(f"<tr>{cells}</tr>")

    if not rows:
        rows.append('<tr><td colspan="9">No findings.</td></tr>')

    severity_rows = "".join(
        f"<tr><th>{severity}</th><td>{count}</td></tr>"
        for severity, count in summary.by_severity.items()
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AWS Security Scanner Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #202124; }}
    h1, h2 {{ margin-bottom: .5rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
    th, td {{ border: 1px solid #d0d7de; padding: .55rem; text-align: left; vertical-align: top; }}
    th {{ background: #f6f8fa; }}
    td {{ overflow-wrap: anywhere; }}
    .summary {{ max-width: 32rem; }}
  </style>
</head>
<body>
  <h1>AWS Security Scanner Report</h1>
  <p>Total findings: <strong>{summary.total_findings}</strong></p>
  <h2>Findings by severity</h2>
  <table class="summary">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{severity_rows}</tbody>
  </table>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Service</th><th>Resource</th><th>Title</th><th>Description</th><th>Remediation</th><th>Region</th><th>Evidence</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</body>
</html>
"""


def write_html_report(
    findings: list[Finding],
    output_path: str | Path,
) -> None:
    """Write a self-contained HTML security report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_html_report(findings),
        encoding="utf-8",
    )
