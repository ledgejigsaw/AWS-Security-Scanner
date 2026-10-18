"""Offline validation primitives for opt-in external Terraform modules."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class ValidatedModuleSource:
    """Canonical source identity suitable for a future isolated module cache."""

    kind: str
    source: str
    immutable_ref: str


def validate_external_module_source(
    source: str,
    *,
    version: str | None = None,
    allowed_git_hosts: tuple[str, ...] = ("github.com",),
) -> ValidatedModuleSource:
    """Validate a pinned Registry or Git source without making network calls.

    Registry sources require namespace/name/provider and exact x.y.z version.
    Git sources require HTTPS and a full 40-character commit SHA in ref.
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("External module source must be a non-empty string.")
    source = source.strip()

    if source.startswith(("./", "../", "/", "~")) or chr(92) in source:
        raise ValueError("Local paths are not external module sources.")

    if source.startswith("git::"):
        if version is not None:
            raise ValueError("Git source pin belongs in the URL ref, not version.")
        parsed = urlsplit(source[5:])
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Git module sources must use HTTPS.")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in source URLs.")
        if parsed.hostname.lower() not in {host.lower() for host in allowed_git_hosts}:
            raise ValueError("Git module host is not allowlisted.")
        if parsed.fragment:
            raise ValueError("Git module source fragments are not supported.")
        refs = parse_qs(parsed.query, keep_blank_values=True).get("ref", [])
        if len(refs) != 1 or not _is_full_commit_sha(refs[0]):
            raise ValueError("Git module source must pin ref to a full commit SHA.")
        return ValidatedModuleSource("git", source, refs[0].lower())

    if "://" in source or source.startswith("git@"):
        raise ValueError("Only Registry or git:: HTTPS sources are supported.")
    parts = source.split("/")
    if len(parts) != 3 or any(not part or part in {".", ".."} for part in parts):
        raise ValueError("Registry source must be namespace/name/provider.")
    if version is None or not _is_exact_semver(version):
        raise ValueError("Registry module source must specify an exact x.y.z version.")
    return ValidatedModuleSource("registry", source, version)


def _is_full_commit_sha(value: str) -> bool:
    return len(value) == 40 and all(c in "0123456789abcdefABCDEF" for c in value)


def _is_exact_semver(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(
        part.isdigit() and (part == "0" or not part.startswith("0"))
        for part in parts
    )
