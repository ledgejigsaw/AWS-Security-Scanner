from pathlib import Path
from typing import Any
import re

import yaml

class YAML12SafeLoader(yaml.SafeLoader):
    """Safe YAML loader using YAML 1.2 boolean semantics."""


YAML12SafeLoader.yaml_implicit_resolvers = {
    key: [
        resolver
        for resolver in resolvers
        if resolver[0] != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}

YAML12SafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)

class SecurityPolicy:
    """Configuration controlling which security rules are enabled."""

    def __init__(
        self,
        rules: dict[str, dict[str, Any]] | None = None,
    ):
        if rules is None:
            rules = {}

        if not isinstance(rules, dict):
            raise TypeError("Policy 'rules' must be a dictionary")

        for check_id, configuration in rules.items():
            if not isinstance(configuration, dict):
                raise TypeError(
                    f"Configuration for rule {check_id} must be a dictionary"
                )

            if "enabled" in configuration:
                if not isinstance(configuration["enabled"], bool):
                    raise TypeError(
                        f"'enabled' for rule {check_id} must be a boolean"
                    )

        self.rules = rules

    def is_enabled(self, check_id: str) -> bool:
        """Return whether a security rule is enabled."""

        configuration = self.rules.get(check_id)

        if configuration is None:
            return True

        return configuration.get("enabled", True)

    @classmethod
    def from_yaml(cls, policy_path: str | Path) -> "SecurityPolicy":
        """Load a security policy from a YAML file."""

        policy_path = Path(policy_path)

        with policy_path.open("r", encoding="utf-8") as file:
            data = yaml.load(file, Loader=YAML12SafeLoader)

        if data is None:
            data = {}

        if not isinstance(data, dict):
            raise TypeError("Policy root must be a dictionary")

        rules = data.get("rules", {})

        if not isinstance(rules, dict):
            raise TypeError("Policy 'rules' must be a dictionary")

        return cls(rules)