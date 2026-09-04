import json
from pathlib import Path

from aws_security_scanner.models.resource import Resource


class FixtureProvider:
    """Load security resources from local JSON fixtures."""

    def __init__(self, fixture_directory: str | Path):
        self.fixture_directory = Path(fixture_directory)

    def discover(self) -> list[Resource]:
        """Discover and normalise all JSON fixtures."""

        resources = []

        for fixture_path in self.fixture_directory.rglob("*.json"):
            with fixture_path.open() as file:
                data = json.load(file)

            resource = self._to_resource(data)
            resources.append(resource)

        return resources

    def _to_resource(self, data: dict) -> Resource:
        """Convert fixture data into the normalised Resource model."""

        return Resource(
            resource_type="aws_s3_bucket",
            resource_id=data["bucket_name"],
            attributes=data,
            source="fixture",
            region=data.get("region"),
        )