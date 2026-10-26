"""Typed cloud-provider discovery boundary.

Provider implementations expose a stable service inventory and return their
read-only discovery operations. Cloud-specific SDKs remain inside providers;
the CLI owns orchestration, coverage recording, rules and reporting.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

from aws_security_scanner.models.resource import Resource


DiscoveryOperationFactory = Callable[[], list[Resource]]


@runtime_checkable
class CloudProvider(Protocol):
    """Minimal structural contract for a read-only cloud discovery provider."""

    provider_name: str
    supported_services: tuple[str, ...]

    def discovery_operations(self) -> Mapping[str, Sequence[DiscoveryOperationFactory]]:
        """Return deterministic service-to-operation mappings for this provider."""
        ...
