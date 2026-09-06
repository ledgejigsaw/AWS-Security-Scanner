import json
from pathlib import Path

from aws_security_scanner.models.resource import Resource


class TerraformProvider:
    """Load and normalise resources from Terraform JSON."""

    def __init__(self, terraform_file: str | Path):
        self.terraform_file = Path(terraform_file)

    def discover(self) -> list[Resource]:
        """Discover Terraform resources and convert them to Resources."""

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

        return resources