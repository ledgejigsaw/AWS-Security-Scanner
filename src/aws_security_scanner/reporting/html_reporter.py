import html
from pathlib import Path

from aws_security_scanner.models.finding import Finding
from aws_security_scanner.reporting.summary import build_summary
from aws_security_scanner.compliance import framework_metadata, mappings_for_check


def build_html_report(
    findings: list[Finding],
    compliance_mapping: dict | None = None,
) -> str:
    """Build a self-contained HTML report with escaped finding content."""
    summary = build_summary(findings)
    rows = []

    include_source_columns = any(finding.source_type != "scanner" for finding in findings)

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
        if include_source_columns:
            values += (
                finding.source_type,
                finding.source_id or "",
                finding.source_product or "",
                finding.first_observed_at or "",
                finding.last_observed_at or "",
            )
        cells = "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in values
        )
        if compliance_mapping is not None:
            mappings = mappings_for_check(compliance_mapping, finding.check_id)
            if mappings:
                mapping_html = "<ul>" + "".join(
                    "<li><strong>"
                    + html.escape(item["control_id"])
                    + " — "
                    + html.escape(item["title"])
                    + "</strong> ("
                    + html.escape(item["confidence"])
                    + "): "
                    + html.escape(item["rationale"])
                    + "</li>"
                    for item in mappings
                ) + "</ul>"
            else:
                mapping_html = "Not mapped"
            cells += f"<td>{mapping_html}</td>"
        rows.append(f"<tr>{cells}</tr>")

    if not rows:
        colspan = (10 if compliance_mapping is not None else 9) + (5 if include_source_columns else 0)
        rows.append(f'<tr><td colspan="{colspan}">No findings.</td></tr>')

    severity_rows = "".join(
        f"<tr><th>{severity}</th><td>{count}</td></tr>"
        for severity, count in summary.by_severity.items()
    )
    source_header = (
        "<th>Source type</th><th>Source finding ID</th><th>Source product</th>"
        "<th>First observed</th><th>Last observed</th>"
        if include_source_columns else ""
    )
    mapping_header = (
        "<th>Compliance mappings</th>"
        if compliance_mapping is not None else ""
    )
    metadata = framework_metadata(compliance_mapping)
    compliance_section = ""
    if metadata is not None:
        compliance_section = (
            "<section><h2>Compliance mapping</h2><p><strong>"
            + html.escape(metadata["name"])
            + " — "
            + html.escape(metadata["version"])
            + "</strong></p><p>"
            + html.escape(metadata["notice"])
            + "</p></section>"
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
  {compliance_section}
  <p>Total findings: <strong>{summary.total_findings}</strong></p>
  <h2>Findings by severity</h2>
  <table class="summary">
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{severity_rows}</tbody>
  </table>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Service</th><th>Resource</th><th>Title</th><th>Description</th><th>Remediation</th><th>Region</th><th>Evidence</th>{source_header}{mapping_header}</tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</body>
</html>
"""


def write_html_report(
    findings: list[Finding],
    output_path: str | Path,
    compliance_mapping: dict | None = None,
) -> None:
    """Write a self-contained HTML security report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_html_report(findings, compliance_mapping),
        encoding="utf-8",
    )
