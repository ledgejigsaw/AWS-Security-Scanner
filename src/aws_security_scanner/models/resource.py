from dataclasses import dataclass
from typing import Any


@dataclass
class Resource:
    resource_type: str
    resource_id: str
    attributes: dict[str, Any]
    source: str
    region: str | None = None