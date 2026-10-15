# Explainable finding risk scoring

Risk scoring is an optional triage aid. It complements the existing finding severity; it does not replace severity, establish compliance or predict breach probability.

## Activation

Enable the version 1 model with:

```bash
aws-security-scan --source terraform --file terraform.json --risk-score --format json
```

By default, risk fields are omitted from JSON, HTML and SARIF to preserve the existing report shape. With `--risk-score`, each finding includes its score, model version and factor explanation. The scanner does not calculate a single aggregate risk score for the whole environment.

## Version 1 formula

```text
score = min(100, round((severity_base + exposure_bonus + resource_criticality_bonus) * detection_confidence))
```

| Severity | Base points |
| --- | ---: |
| CRITICAL | 90 |
| HIGH | 70 |
| MEDIUM | 45 |
| LOW | 25 |
| INFO | 10 |

The default exposure bonus and resource criticality bonus are zero. The default confidence multiplier is 1.0. Missing asset context therefore does not invent additional criticality. Scores are deterministic within model version 1 and capped at 100.

## Optional configuration

A JSON file can apply explicit overrides by check ID and resource identifier:

```json
{
  "version": 1,
  "check_overrides": {
    "S3-001": {
      "exposure_bonus": 10,
      "confidence": 0.8
    }
  },
  "resource_criticality": {
    "company-sensitive-data": 10
  }
}
```

Use it with:

```bash
aws-security-scan --source terraform --file terraform.json --risk-score --risk-config risk.json --format html
```

Validation rules:

- `version` must be `1`.
- `check_overrides` may contain registered check IDs only.
- `exposure_bonus` and resource criticality must be integers from 0 to 10.
- `confidence` must be a number from 0 to 1.
- Unknown fields and malformed JSON are rejected before the scan starts.
- Resource criticality applies only to exact resource identifiers; no automatic business-criticality inference is performed.

## Interpretation and limitations

The score is a configurable prioritisation index, not a probability or prediction of compromise. Exposure and confidence overrides are explicit analyst inputs; the scanner does not infer that a finding is externally exploitable from severity alone. A conditionally constrained cross-account policy can still be an informational review signal and should not be interpreted as proven exposure. Review the factor explanation and source evidence before using a score for remediation ordering.

Model changes that alter the formula or default values require a new model version and regression tests. Existing finding severity and baseline identity are not changed by enabling scoring.
