import json
import re
from pathlib import Path
from typing import Any

from aws_security_scanner.models.resource import Resource


class TerraformProvider:
    """Load and normalise legacy Terraform JSON and terraform show -json plans."""

    def __init__(self, terraform_file: str | Path):
        self.terraform_file = Path(terraform_file)

    def discover(self) -> list[Resource]:
        with self.terraform_file.open(encoding="utf-8") as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError("Terraform JSON root must be an object.")

        if isinstance(data.get("planned_values"), dict) or isinstance(data.get("resource_changes"), list):
            resources = self._discover_plan(data)
        else:
            resources = []
            for resource_type, instances in data.get("resource", {}).items():
                if not isinstance(instances, dict):
                    continue
                for name, attributes in instances.items():
                    if isinstance(attributes, dict):
                        resources.append(Resource(
                            resource_type=resource_type,
                            resource_id=name,
                            attributes=attributes,
                            source="terraform",
                            region=attributes.get("region"),
                        ))
        self._resolve_relationships(resources)
        return resources

    def _discover_plan(self, data: dict[str, Any]) -> list[Resource]:
        changes = {
            item.get("address"): item
            for item in data.get("resource_changes", [])
            if isinstance(item, dict) and isinstance(item.get("address"), str)
        }
        planned: dict[str, dict[str, Any]] = {}
        root = data.get("planned_values", {}).get("root_module", {})
        self._collect_planned_resources(root, planned)

        for address, change in changes.items():
            change_data = change.get("change", {})
            actions = change_data.get("actions", []) if isinstance(change_data, dict) else []
            if "delete" in actions and address not in planned:
                before = change_data.get("before")
                planned[address] = {
                    "address": address,
                    "type": change.get("type"),
                    "name": change.get("name"),
                    "values": before if isinstance(before, dict) else {},
                    "removed": True,
                }

        resources = []
        for address, item in planned.items():
            resource_type, name = item.get("type"), item.get("name")
            if not isinstance(resource_type, str) or not isinstance(name, str):
                continue
            values = item.get("values")
            attributes = dict(values) if isinstance(values, dict) else {}
            change = changes.get(address, {})
            change_data = change.get("change", {}) if isinstance(change, dict) else {}
            actions = change_data.get("actions", []) if isinstance(change_data, dict) else []
            unknown = change_data.get("after_unknown", {}) if isinstance(change_data, dict) else {}
            attributes["terraform_address"] = address
            attributes["terraform_plan_actions"] = list(actions) if isinstance(actions, list) else []
            attributes["terraform_unknown_attributes"] = sorted(set(self._unknown_paths(unknown)))
            if item.get("removed") or (isinstance(actions, list) and actions and set(actions) == {"delete"}):
                attributes["terraform_removed"] = True
            resources.append(Resource(
                resource_type=resource_type,
                resource_id=name,
                attributes=attributes,
                source="terraform",
                region=attributes.get("region"),
            ))
        return resources

    def _collect_planned_resources(self, module: Any, output: dict[str, dict[str, Any]]) -> None:
        if not isinstance(module, dict):
            return
        items = module.get("resources", [])
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict) or item.get("mode", "managed") != "managed":
                    continue
                address = item.get("address")
                if isinstance(address, str):
                    output[address] = item
        children = module.get("child_modules", [])
        if isinstance(children, list):
            for child in children:
                self._collect_planned_resources(child, output)

    def _unknown_paths(self, value: Any, path: str = "") -> list[str]:
        if value is True:
            return [path or "<resource>"]
        if isinstance(value, dict):
            result = []
            for key, nested in value.items():
                child = f"{path}.{key}" if path else str(key)
                result.extend(self._unknown_paths(nested, child))
            return result
        if isinstance(value, list):
            result = []
            for index, nested in enumerate(value):
                result.extend(self._unknown_paths(nested, f"{path}[{index}]"))
            return result
        return []

    def _resolve_relationships(self, resources: list[Resource]) -> None:
        for resource in resources:
            relationships = {}
            self._find_references(resource.attributes, relationships)
            if relationships:
                resource.relationships = relationships

    def _find_references(self, value, relationships: dict[str, str], attribute_name: str | None = None) -> None:
        if isinstance(value, dict):
            for key, nested_value in value.items():
                child_name = f"{attribute_name}.{key}" if attribute_name else key
                self._find_references(nested_value, relationships, attribute_name=child_name)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                child_name = f"{attribute_name}[{index}]" if attribute_name else f"[{index}]"
                self._find_references(item, relationships, attribute_name=child_name)
        elif isinstance(value, str):
            match = re.fullmatch(r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}", value)
            if match and attribute_name:
                relationships[attribute_name] = match.group(1)
