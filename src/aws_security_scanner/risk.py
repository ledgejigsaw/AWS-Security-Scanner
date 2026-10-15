"""Optional, explainable finding risk scoring.

The score is a deterministic triage index, not a probability of compromise.
Severity remains the scanner's primary classification.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aws_security_scanner.models.finding import Finding


MODEL_VERSION = "1"
SEVERITY_BASE = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 45,
    "LOW": 25,
    "INFO": 10,
}


class RiskScoringConfigError(ValueError):
    """Raised when a risk-scoring configuration is malformed or unsafe."""


@dataclass(frozen=True)
class CheckRiskOverride:
    exposure_bonus: int = 0
    confidence: float = 1.0


@dataclass(frozen=True)
class RiskScoringConfig:
    check_overrides: dict[str, CheckRiskOverride] = field(default_factory=dict)
    resource_criticality: dict[str, int] = field(default_factory=dict)


def load_risk_config(
    path: str | Path | None,
    registered_check_ids: set[str],
) -> RiskScoringConfig:
    """Load and validate optional JSON risk configuration.

    Schema v1 permits per-check exposure/confidence overrides and explicit
    resource criticality. Missing asset context adds no criticality bonus.
    """
    if path is None:
        return RiskScoringConfig()
    config_path = Path(path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RiskScoringConfigError(f"Cannot read risk configuration: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RiskScoringConfigError(f"Risk configuration is not valid JSON: {exc}") from exc

    if not isinstance(data, dict) or data.get("version") != 1:
        raise RiskScoringConfigError("Risk configuration must be a JSON object with version: 1.")

    raw_overrides = data.get("check_overrides", {})
    if not isinstance(raw_overrides, dict):
        raise RiskScoringConfigError("'check_overrides' must be a JSON object.")
    overrides: dict[str, CheckRiskOverride] = {}
    for check_id, raw in raw_overrides.items():
        if check_id not in registered_check_ids:
            raise RiskScoringConfigError(f"Unknown check ID in risk configuration: {check_id}")
        if not isinstance(raw, dict):
            raise RiskScoringConfigError(f"Risk override for {check_id} must be an object.")
        unknown_fields = set(raw) - {"exposure_bonus", "confidence"}
        if unknown_fields:
            raise RiskScoringConfigError(
                f"Unsupported risk override field(s) for {check_id}: {', '.join(sorted(unknown_fields))}"
            )
        exposure = raw.get("exposure_bonus", 0)
        confidence = raw.get("confidence", 1.0)
        if isinstance(exposure, bool) or not isinstance(exposure, int) or not 0 <= exposure <= 10:
            raise RiskScoringConfigError(f"exposure_bonus for {check_id} must be an integer from 0 to 10.")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise RiskScoringConfigError(f"confidence for {check_id} must be a number from 0 to 1.")
        overrides[check_id] = CheckRiskOverride(exposure_bonus=exposure, confidence=float(confidence))

    raw_criticality = data.get("resource_criticality", {})
    if not isinstance(raw_criticality, dict):
        raise RiskScoringConfigError("'resource_criticality' must be a JSON object.")
    criticality: dict[str, int] = {}
    for resource, value in raw_criticality.items():
        if not isinstance(resource, str) or not resource.strip():
            raise RiskScoringConfigError("Resource criticality keys must be non-empty resource identifiers.")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10:
            raise RiskScoringConfigError(
                f"Criticality for resource {resource!r} must be an integer from 0 to 10."
            )
        criticality[resource] = value

    unknown_top_level = set(data) - {"version", "check_overrides", "resource_criticality"}
    if unknown_top_level:
        raise RiskScoringConfigError(
            "Unsupported risk configuration field(s): " + ", ".join(sorted(unknown_top_level))
        )
    return RiskScoringConfig(check_overrides=overrides, resource_criticality=criticality)


def score_findings(
    findings: list[Finding],
    config: RiskScoringConfig | None = None,
) -> list[Finding]:
    """Attach deterministic risk scores and factor explanations to findings."""
    config = config or RiskScoringConfig()
    for finding in findings:
        base = SEVERITY_BASE[finding.severity.value]
        override = config.check_overrides.get(finding.check_id, CheckRiskOverride())
        exposure = override.exposure_bonus
        criticality = config.resource_criticality.get(finding.resource, 0)
        confidence = override.confidence
        score = min(100, int(round((base + exposure + criticality) * confidence)))
        finding.risk_score = score
        finding.risk_score_version = MODEL_VERSION
        finding.risk_explanation = {
            "model_version": MODEL_VERSION,
            "severity_base": base,
            "exposure_bonus": exposure,
            "resource_criticality_bonus": criticality,
            "detection_confidence": confidence,
            "formula": "min(100, round((severity_base + exposure_bonus + resource_criticality_bonus) * detection_confidence))",
            "limitations": "Triage index only; not a probability of compromise. Unconfigured criticality and exposure contribute zero.",
        }
    return findings
