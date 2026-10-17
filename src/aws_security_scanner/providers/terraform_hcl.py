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


_NON_LITERAL = object()
_RESOURCE_REFERENCE = re.compile(r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}")


def _unquote_label(value: str) -> str:
    """Remove parser-preserved quotes around HCL block labels."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


class TerraformHCLProvider:
    """Parse Terraform HCL and expand bounded local modules without running Terraform."""

    def __init__(self, hcl_file: str | Path):
        self.hcl_file = Path(hcl_file)

    def discover(self) -> list[Resource]:
        """Discover HCL resources and expand safe local child modules."""
        if not self.hcl_file.exists():
            raise ValueError(f"Terraform HCL path does not exist: '{self.hcl_file}'")
        if self.hcl_file.is_dir():
            module_dir = self.hcl_file.resolve()
            files = self._module_files(module_dir)
            if not files:
                raise ValueError(
                    f"No Terraform HCL files (*.tf) found directly in module directory '{self.hcl_file}'."
                )
            scan_root = module_dir
        else:
            module_dir = self.hcl_file.resolve().parent
            files = [self.hcl_file.resolve()]
            scan_root = module_dir
        resources = self._discover_module(
            module_dir=module_dir, files=files, scan_root=scan_root,
            address_prefix="", input_values={}, active_stack=(), depth=0,
        )
        TerraformProvider(self.hcl_file)._resolve_relationships(resources)
        known_addresses = {item.source_address for item in resources if item.source_address}
        for resource in resources:
            if not resource.source_address or not resource.source_address.startswith("module.") or not resource.relationships:
                continue
            parent_prefix = ".".join(resource.source_address.split(".")[:-2])
            for key, target in list(resource.relationships.items()):
                qualified = f"{parent_prefix}.{target}"
                if qualified in known_addresses:
                    resource.relationships[key] = qualified
        seen: set[tuple[str, str]] = set()
        unique: list[Resource] = []
        for resource in resources:
            identity = (resource.resource_type, resource.source_address or resource.resource_id)
            if identity not in seen:
                seen.add(identity)
                unique.append(resource)
        return unique

    @staticmethod
    def _module_files(module_dir: Path) -> list[Path]:
        """List direct-child HCL files only; nested directories need explicit module sources."""
        return sorted(path.resolve() for path in module_dir.glob("*.tf") if path.is_file())

    def _load_hcl(self, path: Path) -> dict[str, Any]:
        try:
            with path.open(encoding="utf-8") as file:
                data = hcl2.load(file)
        except (OSError, ValueError, LarkError) as error:
            raise ValueError(f"Unable to parse Terraform HCL file '{path}': {error}") from error
        if not isinstance(data, dict):
            raise ValueError(f"Terraform HCL root in '{path}' must be an object.")
        return data

    def _discover_module(
        self, *, module_dir: Path, files: list[Path], scan_root: Path,
        address_prefix: str, input_values: dict[str, Any],
        active_stack: tuple[Path, ...], depth: int,
    ) -> list[Resource]:
        max_depth = 8
        module_dir = module_dir.resolve()
        if module_dir in active_stack:
            raise ValueError(f"Terraform local module cycle detected at '{module_dir}'.")
        if depth > max_depth:
            raise ValueError(f"Terraform local module depth exceeds {max_depth} at '{module_dir}'.")

        variables = self._collect_variable_defaults(files)
        variables.update(input_values)
        resources: list[Resource] = []
        module_calls: list[tuple[str, dict[str, Any], Path]] = []
        for path in files:
            data = self._load_hcl(path)
            resources.extend(self._discover_file(path, variables=variables, address_prefix=address_prefix))
            for block in data.get("module", []) if isinstance(data.get("module", []), list) else []:
                if isinstance(block, dict):
                    for raw_name, attrs in block.items():
                        if isinstance(attrs, dict):
                            module_calls.append((_unquote_label(raw_name), attrs, path))

        for name, attrs, declaring_file in module_calls:
            local = f"module.{name}"
            address = f"{address_prefix}.{local}" if address_prefix else local
            source = self._literal_value(attrs.get("source"))
            if "count" in attrs or "for_each" in attrs:
                self._set_module_diagnostic(
                    resources, address, declaring_file,
                    "Module count/for_each changes module cardinality and is not statically expanded.",
                    source=source if isinstance(source, str) else None,
                )
                continue
            if not isinstance(source, str) or not source.startswith(("./", "../")):
                self._set_module_diagnostic(
                    resources, address, declaring_file,
                    "Only local relative module sources are expanded. Registry, Git and expression-based sources are not downloaded or executed.",
                    source=source if isinstance(source, str) else None,
                )
                continue

            child_dir = (declaring_file.parent / source).resolve()
            try:
                child_dir.relative_to(scan_root.resolve())
            except ValueError:
                self._set_module_diagnostic(resources, address, declaring_file,
                    "The local module source resolves outside the selected scan root and was not followed.", source=source)
                continue
            if child_dir in (*active_stack, module_dir):
                self._set_module_diagnostic(resources, address, declaring_file,
                    "A local module cycle was detected; expansion stopped at this call.", source=source)
                continue
            if depth >= max_depth:
                self._set_module_diagnostic(resources, address, declaring_file,
                    f"The local module expansion depth limit ({max_depth}) was reached.", source=source)
                continue
            if not child_dir.is_dir():
                self._set_module_diagnostic(resources, address, declaring_file,
                    "The local module source directory does not exist.", source=source)
                continue
            child_files = self._module_files(child_dir)
            if not child_files:
                self._set_module_diagnostic(resources, address, declaring_file,
                    "The local module directory contains no top-level .tf files.", source=source)
                continue

            child_inputs: dict[str, Any] = {}
            for raw_key, raw_value in attrs.items():
                key = _unquote_label(str(raw_key))
                if key in {"source", "version", "providers", "depends_on", "count", "for_each", "__is_block__"}:
                    continue
                value = self._literal_value(raw_value)
                if value is not _NON_LITERAL:
                    child_inputs[key] = value
                else:
                    # Preserve unknown caller expressions so they override child defaults
                    # and remain visible as unresolved in the child resources.
                    child_inputs[key] = raw_value

            resources = [resource for resource in resources if not (
                resource.source_address == address
                and resource.attributes.get("hcl_diagnostic") == "module_not_expanded"
            )]
            try:
                expanded = self._discover_module(
                    module_dir=child_dir, files=child_files, scan_root=scan_root,
                    address_prefix=address, input_values=child_inputs,
                    active_stack=(*active_stack, module_dir), depth=depth + 1,
                )
            except ValueError as error:
                self._set_module_diagnostic(resources, address, declaring_file,
                    f"Local module expansion failed: {error}", source=source)
                continue
            resources.extend(expanded)
        return resources

    def _collect_variable_defaults(self, files: list[Path]) -> dict[str, Any]:
        defaults: dict[str, Any] = {}
        for path in files:
            data = self._load_hcl(path)
            blocks = data.get("variable", [])
            if not isinstance(blocks, list):
                continue
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                for raw_name, attrs in block.items():
                    if isinstance(attrs, dict) and "default" in attrs:
                        value = self._literal_value(attrs["default"])
                        if value is not _NON_LITERAL:
                            defaults[_unquote_label(raw_name)] = value
        return defaults

    def _literal_value(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1]
        if isinstance(value, str):
            if chr(36) + "{" in value or re.search(r"\b(?:var|local|module)\.[A-Za-z0-9_-]+", value):
                return _NON_LITERAL
        if isinstance(value, list):
            items = [self._literal_value(item) for item in value]
            return _NON_LITERAL if any(item is _NON_LITERAL for item in items) else items
        if isinstance(value, dict):
            items = {key: self._literal_value(item) for key, item in value.items()}
            return _NON_LITERAL if any(item is _NON_LITERAL for item in items.values()) else items
        return value

    def _set_module_diagnostic(
        self, resources: list[Resource], address: str, source_file: Path,
        reason: str, *, source: str | None = None,
    ) -> None:
        for resource in resources:
            if resource.source_address == address and resource.attributes.get("hcl_diagnostic") == "module_not_expanded":
                resource.attributes["hcl_diagnostic_reason"] = reason
                if source is not None:
                    resource.attributes["module_source"] = source
                return
        attrs: dict[str, Any] = {"hcl_diagnostic": "module_not_expanded", "hcl_diagnostic_reason": reason}
        if source is not None:
            attrs["module_source"] = source
        resources.append(Resource(
            resource_type="terraform_hcl_unsupported", resource_id=address,
            attributes=attrs, source="terraform", source_file=str(source_file), source_address=address,
        ))

    def _discover_file(
        self, path: Path, *, variables: dict[str, Any] | None = None, address_prefix: str = "",
    ) -> list[Resource]:
        data = self._load_hcl(path)
        resources: list[Resource] = []
        blocks = data.get("resource", [])
        if isinstance(blocks, dict):
            for resource_type, instances in blocks.items():
                if isinstance(instances, dict):
                    for name, attrs in instances.items():
                        resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attrs, path, variables or {}, address_prefix))
        elif isinstance(blocks, list):
            for block in blocks:
                if isinstance(block, dict):
                    for resource_type, instances in block.items():
                        if isinstance(instances, dict):
                            for name, attrs in instances.items():
                                resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attrs, path, variables or {}, address_prefix))

        for block in data.get("data", []) if isinstance(data.get("data", []), list) else []:
            if isinstance(block, dict):
                for data_type, instances in block.items():
                    if isinstance(instances, dict):
                        for data_name in instances:
                            addr = f"data.{_unquote_label(data_type)}.{_unquote_label(data_name)}"
                            full = f"{address_prefix}.{addr}" if address_prefix else addr
                            resources.append(Resource(
                                resource_type="terraform_hcl_unsupported", resource_id=full,
                                attributes={"hcl_diagnostic": "data_source_not_evaluated"},
                                source="terraform", source_file=str(path), source_address=full,
                            ))

        for block in data.get("module", []) if isinstance(data.get("module", []), list) else []:
            if isinstance(block, dict):
                for module_name in block:
                    addr = f"module.{_unquote_label(module_name)}"
                    full = f"{address_prefix}.{addr}" if address_prefix else addr
                    resources.append(Resource(
                        resource_type="terraform_hcl_unsupported", resource_id=full,
                        attributes={"hcl_diagnostic": "module_not_expanded"},
                        source="terraform", source_file=str(path), source_address=full,
                    ))
        return resources

    def _make_resource(self, resource_type: str, name: str, raw_attributes: Any, source_file: Path | None = None, variables: dict[str, Any] | None = None, address_prefix: str = "") -> Resource:
        attributes = self._normalise_nested_blocks(raw_attributes if isinstance(raw_attributes, dict) else {})
        attributes = self._substitute_variables(attributes, variables or {})
        unresolved = self._unresolved_expressions(attributes)
        if unresolved:
            attributes = dict(attributes)
            attributes["hcl_unresolved_expressions"] = unresolved
        return Resource(
            resource_type=resource_type,
            resource_id=f"{address_prefix}.{resource_type}.{name}" if address_prefix else name,
            attributes=attributes,
            source="terraform",
            region=attributes.get("region"),
            source_file=str(source_file or self.hcl_file),
            source_address=f"{address_prefix}.{resource_type}.{name}" if address_prefix else f"{resource_type}.{name}",
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

    def _substitute_variables(self, value: Any, variables: dict[str, Any]) -> Any:
        """Substitute only statically known variable references."""
        pattern = re.compile(r"\x24\{var\.([A-Za-z0-9_-]+)\}|(?<![A-Za-z0-9_])var\.([A-Za-z0-9_-]+)(?![A-Za-z0-9_])")
        if isinstance(value, dict):
            return {key: self._substitute_variables(item, variables) for key, item in value.items()}
        if isinstance(value, list):
            return [self._substitute_variables(item, variables) for item in value]
        if not isinstance(value, str):
            return value
        full = pattern.fullmatch(value)
        if full:
            name = full.group(1) or full.group(2)
            return variables.get(name, value)
        def replace(match):
            replacement = variables.get(match.group(1) or match.group(2))
            if replacement is None or isinstance(replacement, (dict, list)):
                return match.group(0)
            return str(replacement)
        return pattern.sub(replace, value)

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
        elif isinstance(value, str):
            if chr(36) + "{" in value:
                references = list(_RESOURCE_REFERENCE.finditer(value))
                remainder = _RESOURCE_REFERENCE.sub("", value)
                if not references or (chr(36) + "{") in remainder:
                    unresolved.append(f"{path}: {value}")
            elif re.search(r"\b(?:var|local|module)\.[A-Za-z0-9_-]+", value):
                unresolved.append(f"{path}: {value}")
        return unresolved
