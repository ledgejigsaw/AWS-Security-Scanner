from typing import Any


class SecurityPolicy:
    """Configuration controlling which security rules are enabled."""

    def __init__(
        self,
        rules: dict[str, dict[str, Any]] | None = None,
    ):
        if rules is None:
            rules = {}

        for check_id, configuration in rules.items():
            if not isinstance(configuration, dict):
                raise TypeError(
                    f"Configuration for rule {check_id} must be a dictionary"
                )

        self.rules = rules

    def is_enabled(self, check_id: str) -> bool:
        """Return whether a security rule is enabled."""

        configuration = self.rules.get(check_id)

        if configuration is None:
            return True

        return configuration.get("enabled", True)