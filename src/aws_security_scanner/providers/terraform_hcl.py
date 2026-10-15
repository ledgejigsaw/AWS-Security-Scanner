"""Offline, conservative Terraform HCL resource loading."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.terraform import TerraformProvider


_RESOURCE_REFERENCE = re.compile(r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}")


class TerraformHCLProvider:
    """Parse literal Terraform HCL without running Terraform or loading modules."""

    def __init__(self, hcl_file: str | Path):
        self.hcl_file = Path(hcl_file)

    def discover(self) -> list[Resource]:
        try:
            with self.hcl_file.open(encoding="utf-8") as file:
                data = hcl2.load(file)
        except (OSError, ValueError) as error:
            raise ValueError(f"Unable to parse Terraform HCL file '{self.hcl_file}': {error}") from error

        if not isinstance(data, dict):
            raise ValueError("Terraform HCL root must be an object.")

        resources: list[Resource] = []
        blocks = data.get("resource", [])
        if isinstance(blocks, dict):
            # Tolerate parsers/fixtures that expose a JSON-like resource mapping.
            for resource_type, instances in blocks.items():
                if not isinstance(instances, dict):
                    continue
                for name, attributes in instances.items():
                    resources.append(self._make_resource(resource_type, name, attributes))
        elif isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                for resource_type, instances in block.items():
                    if not isinstance(instances, dict):
                        continue
                    for name, attributes in instances.items():
                        resources.append(self._make_resource(resource_type, name, attributes))

        # Module code is deliberately not loaded or evaluated. Emit a diagnostic
        # placeholder so reports make this analysis limitation visible.
        modules = data.get("module", [])
        if isinstance(modules, list):
            for module_block in modules:
                if isinstance(module_block, dict):
                    for module_name in module_block:
                        resources.append(
                            Resource(
                                resource_type="terraform_hcl_unsupported",
                                resource_id=f"module.{module_name}",
                                attributes={
                                    "hcl_diagnostic": "module_not_expanded",
                                    "hcl_unresolved_expressions": [
                                        "Module contents were not loaded or evaluated."
                                    ],
                                },
                                source="terraform",
                            )
                        )

        TerraformProvider(self.hcl_file)._resolve_relationships(resources)
        return resources

    def _make_resource(self, resource_type: str, name: str, raw_attributes: Any) -> Resource:
        attributes = raw_attributes if isinstance(raw_attributes, dict) else {}
        unresolved = self._unresolved_expressions(attributes)
        if unresolved:
            attributes = dict(attributes)
            attributes["hcl_unresolved_expressions"] = unresolved
        return Resource(
            resource_type=resource_type,
            resource_id=name,
            attributes=attributes,
            source="terraform",
            region=attributes.get("region"),
        )

    def _unresolved_expressions(self, value: Any, path: str = "") -> list[str]:
        unresolved: list[str] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                # count/for_each are expressions that can change resource cardinality.
                child_path = f"{path}.{key}" if path else str(key)
                if key in {"count", "for_each", "dynamic"}:
                    unresolved.append(f"{child_path}: {nested!r}")
                    continue
                unresolved.extend(self._unresolved_expressions(nested, child_path))
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                unresolved.extend(self._unresolved_expressions(nested, f"{path}[{index}]"))
        elif isinstance(value, str) and "${" in value:
            references = list(_RESOURCE_REFERENCE.finditer(value))
            remainder = _RESOURCE_REFERENCE.sub("", value)
            if not references or "${" in remainder:
                unresolved.append(f"{path}: {value}")
        return unresolved
