"""Reproducible source metadata and optional Checkov/Trivy comparisons."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")


def validate_upstream_metadata(metadata: dict[str, Any]) -> list[str]:
    """Return deterministic validation errors for an imported benchmark source."""
    errors: list[str] = []
    repository = metadata.get("repository")
    commit = metadata.get("commit")
    license_id = metadata.get("license")
    fixture_path = metadata.get("path")
    digest = metadata.get("sha256")
    if not isinstance(repository, str) or not repository.startswith("https://github.com/"):
        errors.append("repository_must_be_github_https_url")
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        errors.append("commit_must_be_full_40_character_sha")
    if not isinstance(license_id, str) or not license_id.strip():
        errors.append("license_must_be_recorded")
    if not isinstance(fixture_path, str) or not fixture_path.strip():
        errors.append("path_must_be_recorded")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        errors.append("sha256_must_be_64_hex_characters")
    return sorted(errors)


def sha256_file(path: str | Path) -> str:
    """Hash fixture bytes so accidental changes are detectable."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_checkov_report(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize Checkov JSON output without inventing scanner-rule mappings."""
    checks = payload.get("results", {}).get("failed_checks", [])
    if not isinstance(checks, list):
        raise ValueError("Checkov JSON results.failed_checks must be a list")
    normalized = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        normalized.append({
            "tool": "checkov",
            "check_id": str(check.get("check_id") or "UNKNOWN"),
            "severity": str(check.get("severity") or "UNKNOWN").upper(),
            "resource_address": str(check.get("resource") or ""),
            "source_file": str(check.get("file_path") or ""),
            "title": str(check.get("check_name") or ""),
        })
    return sorted(normalized, key=lambda item: (item["source_file"], item["resource_address"], item["check_id"]))


def normalize_trivy_report(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize Trivy config misconfiguration JSON output."""
    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy JSON Results must be a list")
    normalized = []
    for result in results:
        if not isinstance(result, dict):
            continue
        items = result.get("Misconfigurations", []) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            cause = item.get("CauseMetadata")
            cause = cause if isinstance(cause, dict) else {}
            normalized.append({
                "tool": "trivy",
                "check_id": str(item.get("ID") or "UNKNOWN"),
                "severity": str(item.get("Severity") or "UNKNOWN").upper(),
                "resource_address": str(cause.get("Resource") or ""),
                "source_file": str(result.get("Target") or ""),
                "title": str(item.get("Title") or ""),
            })
    return sorted(normalized, key=lambda item: (item["source_file"], item["resource_address"], item["check_id"]))


def run_optional_iac_tool(tool: str, path: str | Path, *, timeout_seconds: int = 120) -> dict[str, Any]:
    """Run Checkov or Trivy when installed; never install tools implicitly."""
    if tool not in {"checkov", "trivy"}:
        raise ValueError("tool must be 'checkov' or 'trivy'")
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be positive")
    executable = shutil.which(tool)
    if executable is None:
        return {"tool": tool, "status": "unavailable", "findings": [], "diagnostics": ["tool_not_installed"]}
    target = str(Path(path))
    command = ([executable, "-f", target, "-o", "json"] if tool == "checkov"
               else [executable, "config", "--format", "json", target])
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return {"tool": tool, "status": "failed", "findings": [], "diagnostics": ["timeout"]}
    if completed.returncode not in {0, 1}:
        return {"tool": tool, "status": "failed", "findings": [], "diagnostics": ["nonzero_exit"]}
    try:
        payload = json.loads(completed.stdout)
        findings = normalize_checkov_report(payload) if tool == "checkov" else normalize_trivy_report(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {"tool": tool, "status": "failed", "findings": [], "diagnostics": ["invalid_json_output"]}
    return {
        "tool": tool,
        "status": "complete",
        "return_code": completed.returncode,
        "findings": findings,
        "diagnostics": [],
    }
