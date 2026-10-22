"""Conservative structural analysis of AWS IAM policy documents."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any

def _string_list(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str) and value:
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        return tuple(sorted(set(value)))
    # IAM Principal/NotPrincipal may be a mapping such as {"AWS": ["arn:..."]}.
    # Flatten only known string/list values into deterministic typed tokens.
    if isinstance(value, dict) and value:
        tokens: list[str] = []
        for principal_type, principals in value.items():
            parsed = _string_list(principals)
            if not isinstance(principal_type, str) or parsed is None:
                return None
            tokens.extend(f"{principal_type}:{principal}" for principal in parsed)
        return tuple(sorted(set(tokens))) if tokens else None
    return None

@dataclass(frozen=True)
class IAMStatementAnalysis:
    index: int
    effect: str | None
    actions: tuple[str, ...] | None
    not_actions: tuple[str, ...] | None
    resources: tuple[str, ...] | None
    not_resources: tuple[str, ...] | None
    principals: tuple[str, ...] | None
    not_principals: tuple[str, ...] | None
    condition_operators: tuple[str, ...]
    condition_keys: tuple[str, ...]
    unconditional_allow: bool
    global_action_resource_allow: bool
    unsupported_or_incomplete: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key, value in result.items():
            if isinstance(value, tuple):
                result[key] = list(value)
        return result

def analyse_iam_statement(statement: Any, index: int = 0) -> IAMStatementAnalysis:
    """Normalise supported statement fields without evaluating authorization."""
    missing: list[str] = []
    if not isinstance(statement, dict):
        return IAMStatementAnalysis(index, None, None, None, None, None, None, None, (), (), False, False,
                                    ("statement_not_object",))
    effect = statement.get("Effect") if isinstance(statement.get("Effect"), str) else None
    if effect not in {"Allow", "Deny"}:
        missing.append("effect_missing_or_invalid")
    parsed = {}
    for field in ("Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal"):
        parsed[field] = _string_list(statement.get(field)) if field in statement else None
        if field in statement and parsed[field] is None:
            missing.append(field.lower() + "_unsupported_shape")
    if parsed["Action"] is None and parsed["NotAction"] is None:
        missing.append("action_scope_missing")
    if parsed["Resource"] is None and parsed["NotResource"] is None:
        missing.append("resource_scope_missing")
    condition = statement.get("Condition")
    operators: tuple[str, ...] = ()
    keys: tuple[str, ...] = ()
    if condition is not None:
        if not isinstance(condition, dict):
            missing.append("condition_unsupported_shape")
        else:
            operators = tuple(sorted(str(key) for key in condition))
            keys = tuple(sorted({str(key) for values in condition.values()
                                 if isinstance(values, dict) for key in values}))
            if any(not isinstance(values, dict) for values in condition.values()):
                missing.append("condition_operator_values_unsupported")
    actions, resources = parsed["Action"], parsed["Resource"]
    return IAMStatementAnalysis(
        index, effect, actions, parsed["NotAction"], resources, parsed["NotResource"],
        parsed["Principal"], parsed["NotPrincipal"], operators, keys,
        effect == "Allow" and condition is None,
        effect == "Allow" and actions == ("*",) and resources == ("*",),
        tuple(sorted(set(missing))),
    )

def analyse_iam_policy(policy_document: Any) -> dict[str, Any]:
    """Return deterministic structural analysis with explicit completeness limits."""
    if not isinstance(policy_document, dict):
        return {"status": "unknown", "reason": "policy_document_not_object", "statements": [],
                "limitations": ["Missing or malformed policy data cannot establish effective access."]}
    raw = policy_document.get("Statement")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return {"status": "unknown", "reason": "statement_collection_missing_or_invalid", "statements": [],
                "limitations": ["Missing or malformed statements cannot establish effective access."]}
    statements = [analyse_iam_statement(item, index).to_dict() for index, item in enumerate(raw)]
    incomplete = any(item["unsupported_or_incomplete"] for item in statements)
    return {
        "status": "partial" if incomplete else "structural_analysis_complete",
        "statement_count": len(statements),
        "statements": statements,
        "limitations": [
            "This is structural analysis, not an AWS authorization simulator.",
            "Effective access also depends on identity/resource policies, SCPs, permissions boundaries, session policies, trust context and service-specific controls.",
            "Condition keys and operators are recorded but not evaluated; conditions must not automatically be treated as safe.",
        ],
    }
