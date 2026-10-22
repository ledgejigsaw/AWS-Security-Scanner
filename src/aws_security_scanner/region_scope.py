"""Explicit AWS region-scope planning and bounded region enumeration."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any, Iterable

@dataclass(frozen=True)
class RegionScope:
    selected_regions: tuple[str, ...]
    excluded_regions: tuple[str, ...]
    global_service_scopes: tuple[str, ...]
    enumeration_status: str
    diagnostics: tuple[str, ...] = ()
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def resolve_region_scope(*, enabled_regions: Iterable[str], default_region: str | None = None,
                         all_enabled_regions: bool = False, include_regions: Iterable[str] = (),
                         exclude_regions: Iterable[str] = (), global_service_scopes: Iterable[str] = (),
                         enumeration_status: str = "success") -> RegionScope:
    """Resolve selection without substituting a default after failed enumeration."""
    includes = tuple(sorted(set(str(x).strip() for x in include_regions if str(x).strip())))
    excludes = tuple(sorted(set(str(x).strip() for x in exclude_regions if str(x).strip())))
    globals_ = tuple(sorted(set(str(x).strip() for x in global_service_scopes if str(x).strip())))
    if enumeration_status not in {"success", "denied", "failed", "not_attempted"}:
        raise ValueError("invalid enumeration_status")
    if enumeration_status != "success":
        return RegionScope((), excludes, globals_, enumeration_status,
                           (f"enabled-region enumeration {enumeration_status}; regional coverage is incomplete",))
    enabled = set(str(x).strip() for x in enabled_regions if str(x).strip())
    if not enabled:
        return RegionScope((), excludes, globals_, "success", ("no enabled regions were returned",))
    diagnostics = [f"requested region is not enabled: {x}" for x in sorted(set(includes) - enabled)]
    selected = set(enabled if all_enabled_regions else includes)
    if not all_enabled_regions and not includes:
        if default_region and default_region in enabled:
            selected.add(default_region)
        elif default_region:
            diagnostics.append(f"default region is not enabled: {default_region}")
        else:
            diagnostics.append("no explicit region or enabled default region was selected")
    selected.difference_update(excludes)
    selected.intersection_update(enabled)
    return RegionScope(tuple(sorted(selected)), tuple(sorted(set(excludes) & enabled)), globals_,
                       "success", tuple(sorted(diagnostics)))

def enumerate_enabled_regions(ec2_client: Any, *, max_pages: int = 100) -> tuple[str, ...]:
    """Call DescribeRegions(AllRegions=False); propagate access and API failures."""
    if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
        raise ValueError("max_pages must be a positive integer")
    token = None
    seen = set()
    regions = set()
    for _ in range(max_pages):
        kwargs = {"AllRegions": False}
        if token:
            kwargs["NextToken"] = token
        response = ec2_client.describe_regions(**kwargs)
        for item in response.get("Regions", []):
            if isinstance(item, dict) and isinstance(item.get("RegionName"), str):
                regions.add(item["RegionName"])
        token = response.get("NextToken")
        if not token:
            return tuple(sorted(regions))
        if not isinstance(token, str) or token in seen:
            raise RuntimeError("DescribeRegions returned a repeated or invalid pagination token")
        seen.add(token)
    raise RuntimeError("region enumeration exceeded max_pages; coverage is incomplete")
