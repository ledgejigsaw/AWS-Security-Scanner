"""Offline, conservative Terraform HCL resource loading."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import hcl2
from lark.exceptions import LarkError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.terraform import TerraformProvider


_RESOURCE_REFERENCE = re.compile(r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}")


def _unquote_label(value: str) -> str:
    """Remove parser-preserved quotes around HCL block labels."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


class TerraformHCLProvider:
    """Parse literal Terraform HCL without running Terraform or loading modules."""

    def __init__(self, hcl_file: str | Path):
        self.hcl_file = Path(hcl_file)

    def discover(self) -> list[Resource]:
        """Discover resources from one HCL file or all .tf files in a module root.

        Directory mode deliberately reads only direct children. Nested directories
        are separate Terraform module/example boundaries and are never merged
        implicitly.
        """
        if not self.hcl_file.exists():
            raise ValueError(f"Terraform HCL path does not exist: '{self.hcl_file}'")
        if self.hcl_file.is_dir():
            files = sorted(path for path in self.hcl_file.glob("*.tf") if path.is_file())
            if not files:
                raise ValueError(
                    f"No Terraform HCL files (*.tf) found directly in module directory '{self.hcl_file}'. "
                    "Nested directories are treated as separate modules; scan the intended module directory."
                )
        else:
            files = [self.hcl_file]

        resources: list[Resource] = []
        seen: set[tuple[str, str]] = set()
        for path in files:
            for resource in self._discover_file(path):
                identity = (resource.resource_type, resource.source_address or resource.resource_id)
                if identity in seen:
                    continue
                seen.add(identity)
                resources.append(resource)

        # Resolve references after combining files so resources declared in
        # separate .tf files can still be linked together.
        TerraformProvider(self.hcl_file)._resolve_relationships(resources)
        return resources

    def _discover_file(self, path: Path) -> list[Resource]:
        try:
            with path.open(encoding="utf-8") as file:
                data = hcl2.load(file)
        except (OSError, ValueError, LarkError) as error:
            raise ValueError(f"Unable to parse Terraform HCL file '{path}': {error}") from error

        if not isinstance(data, dict):
            raise ValueError(f"Terraform HCL root in '{path}' must be an object.")

        resources: list[Resource] = []
        blocks = data.get("resource", [])
        if isinstance(blocks, dict):
            # Tolerate parsers/fixtures that expose a JSON-like resource mapping.
            for resource_type, instances in blocks.items():
                if not isinstance(instances, dict):
                    continue
                for name, attributes in instances.items():
                    resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attributes, path))
        elif isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                for resource_type, instances in block.items():
                    if not isinstance(instances, dict):
                        continue
                    for name, attributes in instances.items():
                        resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attributes, path))

        # Data sources are not queried or evaluated. A dedicated diagnostic
        # prevents this limitation from being mislabelled as an unresolved
        # expression on the resource itself.
        data_blocks = data.get("data", [])
        if isinstance(data_blocks, list):
            for data_block in data_blocks:
                if not isinstance(data_block, dict):
                    continue
                for data_type, instances in data_block.items():
                    if not isinstance(instances, dict):
                        continue
                    for data_name in instances:
                        address = f"data.{_unquote_label(data_type)}.{_unquote_label(data_name)}"
                        resources.append(Resource(
                            resource_type="terraform_hcl_unsupported",
                            resource_id=address,
                            attributes={"hcl_diagnostic": "data_source_not_evaluated"},
                            source="terraform",
                            source_file=str(path),
                            source_address=address,
                        ))

        # Child module source is deliberately not loaded or evaluated.
        modules = data.get("module", [])
        if isinstance(modules, list):
            for module_block in modules:
                if isinstance(module_block, dict):
                    for module_name in module_block:
                        address = f"module.{_unquote_label(module_name)}"
                        resources.append(Resource(
                            resource_type="terraform_hcl_unsupported",
                            resource_id=address,
                            attributes={"hcl_diagnostic": "module_not_expanded"},
                            source="terraform",
                            source_file=str(path),
                            source_address=address,
                        ))
        return resources

    def _make_resource(self, resource_type: str, name: str, raw_attributes: Any, source_file: Path | None = None) -> Resource:
        attributes = self._normalise_nested_blocks(raw_attributes if isinstance(raw_attributes, dict) else {})
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
            source_file=str(source_file or self.hcl_file),
            source_address=f"{resource_type}.{name}",
        )

    def _normalise_nested_blocks(self, attributes: dict[str, Any]) -> dict[str, Any]:
        """Flatten known singleton HCL blocks into the JSON-like rule model."""
        result: dict[str, Any] = {}
        block_names = {
            "versioning_configuration",
            "rule",
            "server_side_encryption_configuration",
            "public_access_block",
            "logging",
            "lifecycle_rule",
        }
        for key, value in attributes.items():
            # python-hcl2 preserves quoted literal strings and adds this marker
            # to nested block dictionaries; neither belongs in normalized attrs.
            if key == "__is_block__":
                continue
            if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
            if key in block_names and isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                result[key] = self._normalise_nested_blocks(value[0])
            elif isinstance(value, dict):
                result[key] = self._normalise_nested_blocks(value)
            elif isinstance(value, list):
                result[key] = [
                    self._normalise_nested_blocks(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

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
