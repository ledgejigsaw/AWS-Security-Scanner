"""Read-only multi-region orchestration primitives.

The module is independent of the CLI so callers can opt into multi-region
scanning without changing the existing explicit single-region contract.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable


@dataclass(frozen=True, slots=True)
class RegionState:
    name: str
    status: str
    opt_in_status: str | None = None


@dataclass(frozen=True, slots=True)
class RegionResult:
    region: str
    status: str
    resources_discovered: int = 0
    error_category: str | None = None


def classify_regions(response: dict[str, Any]) -> tuple[list[RegionState], list[RegionState]]:
    """Return enabled and skipped regions from EC2 DescribeRegions(AllRegions=True)."""
    regions = response.get("Regions", [])
    if not isinstance(regions, list):
        raise ValueError("DescribeRegions response Regions must be a list")
    enabled: list[RegionState] = []
    skipped: list[RegionState] = []
    for item in regions:
        if not isinstance(item, dict):
            continue
        name = item.get("RegionName")
        if not isinstance(name, str) or not name:
            continue
        opt_in = item.get("OptInStatus")
        state = RegionState(name=name, status="enabled" if opt_in in {"opt-in-not-required", "opted-in"} else "skipped", opt_in_status=opt_in)
        (enabled if state.status == "enabled" else skipped).append(state)
    return sorted(enabled, key=lambda item: item.name), sorted(skipped, key=lambda item: item.name)


def scan_regions(
    regions: Iterable[str],
    scan_region: Callable[[str], list[Any]],
    *,
    global_scan: Callable[[], list[Any]] | None = None,
) -> dict[str, Any]:
    """Scan each region independently and run global discovery at most once.

    Exceptions are converted to safe error categories; their messages and
    resource payloads are not serialized. Successful regions are retained if
    another region fails.
    """
    resources: list[Any] = []
    results: list[RegionResult] = []
    for region in sorted(set(regions)):
        if not isinstance(region, str) or not region.strip():
            raise ValueError("region names must be non-empty strings")
        try:
            found = scan_region(region)
            if not isinstance(found, list):
                raise TypeError("regional scan must return a list")
        except Exception as exc:
            results.append(RegionResult(region, "failed", error_category=_safe_error_category(exc)))
            continue
        resources.extend(found)
        results.append(RegionResult(region, "success", resources_discovered=len(found)))

    global_result = {"status": "not_requested", "resources_discovered": 0}
    if global_scan is not None:
        try:
            global_resources = global_scan()
            if not isinstance(global_resources, list):
                raise TypeError("global scan must return a list")
        except Exception as exc:
            global_result = {"status": "failed", "resources_discovered": 0, "error_category": _safe_error_category(exc)}
        else:
            resources.extend(global_resources)
            global_result = {"status": "success", "resources_discovered": len(global_resources)}

    return {
        "schema_version": "1.0.0",
        "status": "incomplete" if any(item.status == "failed" for item in results) or global_result["status"] == "failed" else "complete",
        "regions_attempted": [item.region for item in results],
        "regions_failed": [item.region for item in results if item.status == "failed"],
        "regions": [asdict(item) for item in results],
        "global_discovery": global_result,
        "resources": resources,
    }


def _safe_error_category(error: Exception) -> str:
    """Classify an exception without serializing potentially sensitive text."""
    name = type(error).__name__.lower()
    if "accessdenied" in name or "unauthorized" in name or "permission" in name:
        return "authorization"
    if "throttl" in name or "rate" in name:
        return "throttling"
    if "endpoint" in name or "unknownservice" in name:
        return "unsupported_or_unavailable"
    if isinstance(error, (TypeError, ValueError)):
        return "invalid_response"
    return "unexpected_error"
