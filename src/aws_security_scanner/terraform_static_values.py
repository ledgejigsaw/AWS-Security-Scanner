"""Conservative resolver for statically known Terraform attribute values.

This module deliberately resolves only exact references supplied by the HCL
normaliser and literal values. It never evaluates Terraform expressions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re

_REFERENCE = re.compile(r"^(?:var|local|module|data|[A-Za-z0-9_]+)\.[A-Za-z0-9_][A-Za-z0-9_.\[\]-]*$")


@dataclass(frozen=True)
class StaticResolution:
    """A value resolution with explicit uncertainty instead of unsafe guesses."""
    value: Any = None
    resolved: bool = False
    reason: str | None = None
    chain: tuple[str, ...] = ()


class StaticValueResolver:
    """Resolve literal values and exact known-reference aliases with depth bounds."""
    def __init__(self, known_values: dict[str, Any], *, max_depth: int = 32) -> None:
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
            raise ValueError("max_depth must be a positive integer")
        self._values = dict(known_values)
        self._max_depth = max_depth

    def resolve(self, expression: Any) -> StaticResolution:
        """Resolve a literal or a simple reference key without expression evaluation."""
        if not isinstance(expression, str):
            return StaticResolution(value=expression, resolved=True, chain=())
        current = expression.strip()
        if current in self._values:
            return self._resolve_key(current, (), 0)
        if _REFERENCE.fullmatch(current):
            return StaticResolution(reason="reference_not_found", chain=(current,))
        return StaticResolution(reason="unsupported_expression", chain=(current,))

    def _resolve_key(self, key: str, stack: tuple[str, ...], depth: int) -> StaticResolution:
        if key in stack:
            return StaticResolution(reason="reference_cycle", chain=stack + (key,))
        if depth >= self._max_depth:
            return StaticResolution(reason="maximum_resolution_depth", chain=stack + (key,))
        if key not in self._values:
            return StaticResolution(reason="reference_not_found", chain=stack + (key,))
        value = self._values[key]
        if not isinstance(value, str):
            return StaticResolution(value=value, resolved=True, chain=stack + (key,))
        candidate = value.strip()
        if candidate in self._values:
            return self._resolve_key(candidate, stack + (key,), depth + 1)
        if _REFERENCE.fullmatch(candidate):
            return StaticResolution(reason="reference_not_found", chain=stack + (key, candidate))
        return StaticResolution(reason="unsupported_expression", chain=stack + (key, candidate))
