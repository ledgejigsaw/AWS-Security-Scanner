import json
import re
from pathlib import Path

from aws_security_scanner.models.resource import Resource


class TerraformProvider:
    """Load and normalise resources from Terraform JSON."""

    def __init__(self, terraform_file: str | Path):
        self.terraform_file = Path(terraform_file)

    def discover(self) -> list[Resource]:
        """Discover Terraform resources and establish relationships."""

        with self.terraform_file.open() as file:
            data = json.load(file)

        resources = []

        for resource_type, resource_instances in data.get(
            "resource", {}
        ).items():

            for resource_name, attributes in resource_instances.items():
                resources.append(
                    Resource(
                        resource_type=resource_type,
                        resource_id=resource_name,
                        attributes=attributes,
                        source="terraform",
                        region=attributes.get("region"),
                    )
                )

        self._resolve_relationships(resources)

        return resources

    def _resolve_relationships(self, resources: list[Resource]) -> None:
        """Resolve Terraform resource references into relationships."""

        for resource in resources:
            relationships = {}

            self._find_references(
                resource.attributes,
                relationships,
            )

            if relationships:
                resource.relationships = relationships

    def _find_references(
        self,
        value,
        relationships: dict[str, str],
        attribute_name: str | None = None,
    ) -> None:
        """Recursively find Terraform resource references."""

        if isinstance(value, dict):
            for key, nested_value in value.items():
                child_name = (
                    f"{attribute_name}.{key}"
                    if attribute_name
                    else key
                )
                self._find_references(
                    nested_value,
                    relationships,
                    attribute_name=child_name,
                )

        elif isinstance(value, list):
            for index, item in enumerate(value):
                child_name = (
                    f"{attribute_name}[{index}]"
                    if attribute_name
                    else f"[{index}]"
                )
                self._find_references(
                    item,
                    relationships,
                    attribute_name=child_name,
                )

        elif isinstance(value, str):
            match = re.fullmatch(
                r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}",
                value,
            )

            if match and attribute_name:
                relationships[attribute_name] = match.group(1)