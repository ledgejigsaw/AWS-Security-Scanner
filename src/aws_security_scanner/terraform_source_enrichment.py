"""Conservative source attribution for Terraform plan resources.

Plan JSON does not carry HCL line/column spans. This module links resources only
when their canonical Terraform addresses match exactly; it never guesses spans.
"""
from __future__ import annotations
from pathlib import Path
from typing import Iterable

from aws_security_scanner.models.resource import Resource


def enrich_plan_resources(resources: Iterable[Resource], source_config: str | Path) -> list[Resource]:
    """Attach HCL source path/address to exact plan-address matches.

    Unknown values and plan actions remain authoritative in the plan attributes.
    HCL literals are not copied over plan values, since planned values reflect
    variable overrides and provider evaluation more accurately.
    """
    from aws_security_scanner.providers.terraform_hcl import TerraformHCLProvider

    source_path = Path(source_config)
    source_resources = TerraformHCLProvider(source_path).discover()
    by_address: dict[str, list[Resource]] = {}
    for source in source_resources:
        if source.resource_type == "terraform_hcl_unsupported" or not source.source_address:
            continue
        by_address.setdefault(source.source_address, []).append(source)

    enriched: list[Resource] = []
    for resource in resources:
        address = resource.attributes.get("terraform_address")
        if not isinstance(address, str):
            enriched.append(resource)
            continue
        matches = by_address.get(address, [])
        if len(matches) == 1:
            source = matches[0]
            resource.source_file = source.source_file
            resource.source_address = source.source_address
            resource.attributes["terraform_source_match"] = "exact"
        elif len(matches) > 1:
            resource.attributes["terraform_source_match"] = "ambiguous"
            resource.attributes["terraform_source_diagnostic"] = "Multiple HCL resources share this canonical address."
        else:
            resource.attributes["terraform_source_match"] = "unmatched"
            resource.attributes["terraform_source_diagnostic"] = (
                "No exact HCL address match was found. Count/for_each instances, generated resources, "
                "module expansion differences or a different source root may explain the mismatch."
            )
        enriched.append(resource)
    return enriched
