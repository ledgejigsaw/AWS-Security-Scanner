"""Structured, deterministic outcomes for individual discovery operations.

Coverage records deliberately avoid storing raw AWS error messages or response
payloads. They are safe to include in machine-readable assessment reports.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class DiscoveryOutcome(StrEnum):
    SUCCESS = "success"
    ACCESS_DENIED = "access_denied"
    UNSUPPORTED = "unsupported"
    DISABLED = "disabled"
    THROTTLED = "throttled"
    FAILED = "failed"
    SKIPPED = "skipped"


# Only map actions where the API operation-to-IAM-action relationship is known.
# Unknown mappings stay null; do not guess an IAM permission.
KNOWN_IAM_ACTIONS: dict[tuple[str, str], str] = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3", "GetBucketPolicy"): "s3:GetBucketPolicy",
    ("ec2", "DescribeRegions"): "ec2:DescribeRegions",
    ("ec2", "DescribeInstances"): "ec2:DescribeInstances",
    ("iam", "ListPolicies"): "iam:ListPolicies",
    ("iam", "GetPolicyVersion"): "iam:GetPolicyVersion",
    ("sts", "GetCallerIdentity"): "sts:GetCallerIdentity",
}


@dataclass(frozen=True, slots=True)
class DiscoveryOperation:
    service: str
    operation: str
    scope: str
    outcome: DiscoveryOutcome
    resources_discovered: int = 0
    pages: int = 0
    pagination_complete: bool | None = None
    error_category: str | None = None
    iam_action: str | None = None

    def __post_init__(self) -> None:
        if not self.service.strip() or not self.operation.strip() or not self.scope.strip():
            raise ValueError("service, operation, and scope must be non-empty")
        if self.resources_discovered < 0 or self.pages < 0:
            raise ValueError("resource and page counts cannot be negative")
        if self.outcome == DiscoveryOutcome.SUCCESS and self.error_category:
            raise ValueError("successful operations cannot have an error category")
        if self.outcome != DiscoveryOutcome.SUCCESS and self.pagination_complete is True:
            raise ValueError("failed or skipped operations cannot claim complete pagination")

    @classmethod
    def for_operation(
        cls,
        service: str,
        operation: str,
        scope: str,
        outcome: DiscoveryOutcome,
        **kwargs: Any,
    ) -> "DiscoveryOperation":
        return cls(
            service=service,
            operation=operation,
            scope=scope,
            outcome=outcome,
            iam_action=KNOWN_IAM_ACTIONS.get((service, operation)),
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-compatible representation."""
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result


def summarise_discovery_operations(
    operations: list[DiscoveryOperation],
) -> dict[str, Any]:
    """Summarise operation outcomes; successful empty results remain successes."""
    ordered = sorted(operations, key=lambda item: (item.scope, item.service, item.operation))
    counts = {outcome.value: 0 for outcome in DiscoveryOutcome}
    for operation in ordered:
        counts[operation.outcome.value] += 1
    incomplete = any(
        item.outcome not in {DiscoveryOutcome.SUCCESS, DiscoveryOutcome.SKIPPED}
        or item.pagination_complete is False
        for item in ordered
    )
    return {
        "schema_version": "1.0.0",
        "status": "incomplete" if incomplete else "complete",
        "operation_count": len(ordered),
        "outcome_counts": counts,
        "resources_discovered": sum(item.resources_discovered for item in ordered),
        "operations": [item.to_dict() for item in ordered],
    }


def classify_discovery_error(error: Exception) -> tuple[DiscoveryOutcome, str]:
    """Map errors to safe categories without serializing request details."""
    code = ""
    if hasattr(error, "response"):
        response = getattr(error, "response", {})
        if isinstance(response, dict):
            detail = response.get("Error", {})
            if isinstance(detail, dict):
                code = str(detail.get("Code", ""))
    lowered = (code or type(error).__name__).lower()
    if any(token in lowered for token in ("accessdenied", "unauthorized", "notauthorized", "forbidden")):
        return DiscoveryOutcome.ACCESS_DENIED, "authorization"
    if any(token in lowered for token in ("throttl", "requestlimit", "toomanyrequests")):
        return DiscoveryOutcome.THROTTLED, "throttling"
    if any(token in lowered for token in ("notenabled", "disabled", "subscriptionrequired")):
        return DiscoveryOutcome.DISABLED, "service_disabled"
    if any(token in lowered for token in ("unknownoperation", "unknownservice", "unsupported")):
        return DiscoveryOutcome.UNSUPPORTED, "unsupported_operation"
    return DiscoveryOutcome.FAILED, "discovery_failed"
