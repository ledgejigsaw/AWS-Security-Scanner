"""Bounded, opt-in downloader for pinned public GitHub Terraform modules.

Downloaded source is data only: this module never invokes Terraform, providers,
provisioners, scripts or Git. Registry modules remain validation-only until a
separate registry resolver is implemented.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import tempfile
from urllib.request import Request, urlopen
from zipfile import ZipFile, BadZipFile

from aws_security_scanner.terraform_external_modules import validate_external_module_source


def fetch_pinned_github_module(source: str, cache_dir: str | Path, *, enabled: bool = False, allowed_repositories: tuple[str, ...] = (), timeout_seconds: float = 10.0, max_download_bytes: int = 20_000_000, max_files: int = 2_000, max_unpacked_bytes: int = 50_000_000) -> dict[str, str]:
    """Download a pinned GitHub repository ZIP to an isolated content-addressed cache.

    Network access is denied unless enabled=True. Only a root-module archive
    from an explicitly allowlisted owner/repository and full commit SHA is
    supported. Files are extracted manually after traversal, symlink, count and
    size checks; no archive-provided paths are trusted.
    """
    if not enabled:
        raise PermissionError("External module fetching is disabled; explicitly set enabled=True")
    for name, value in (("timeout_seconds", timeout_seconds), ("max_download_bytes", max_download_bytes), ("max_files", max_files), ("max_unpacked_bytes", max_unpacked_bytes)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"{name} must be positive")
    validated = validate_external_module_source(source)
    if validated.kind != "git":
        raise ValueError("This downloader supports pinned GitHub sources only; Registry sources are validation-only")
    from urllib.parse import urlsplit, parse_qs
    parsed = urlsplit(source[5:])
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2 or not parts[1].endswith(".git"):
        raise ValueError("Only root modules from owner/repository.git sources are supported")
    owner, repository = parts[0], parts[1][:-4]
    identity = f"{owner}/{repository}"
    if identity not in set(allowed_repositories):
        raise PermissionError("GitHub module repository is not explicitly allowlisted")
    ref = validated.immutable_ref
    digest = hashlib.sha256(f"{identity}@{ref}".encode()).hexdigest()
    cache_root = Path(cache_dir).expanduser().resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    target = cache_root / digest
    marker = target / ".scanner-module.json"
    if marker.is_file():
        return {"path": str(target), "source": identity, "ref": ref, "sha256": marker.read_text(encoding="utf-8").strip(), "cached": "true"}

    url = f"https://codeload.github.com/{owner}/{repository}/zip/{ref}"
    request = Request(url, headers={"User-Agent": "aws-security-scanner-module-fetch/1"})
    with urlopen(request, timeout=float(timeout_seconds)) as response:
        length = response.headers.get("Content-Length")
        if length and int(length) > max_download_bytes:
            raise ValueError("Module archive exceeds max_download_bytes")
        archive_bytes = response.read(max_download_bytes + 1)
    if len(archive_bytes) > max_download_bytes:
        raise ValueError("Module archive exceeds max_download_bytes")
    archive_hash = hashlib.sha256(archive_bytes).hexdigest()
    try:
        archive = ZipFile(io.BytesIO(archive_bytes))
    except BadZipFile as exc:
        raise ValueError("GitHub returned an invalid module archive") from exc
    entries = [item for item in archive.infolist() if not item.is_dir()]
    if len(entries) > max_files:
        raise ValueError("Module archive exceeds max_files")
    root_prefix = None
    safe_entries = []
    unpacked = 0
    for item in entries:
        path = PurePosixPath(item.filename)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("Module archive contains an unsafe path")
        mode = item.external_attr >> 16
        if mode & 0o170000 == 0o120000:
            raise ValueError("Module archive contains a symbolic link")
        if root_prefix is None:
            root_prefix = path.parts[0]
        if path.parts[0] != root_prefix or len(path.parts) < 2:
            raise ValueError("Module archive has an unexpected root layout")
        relative = PurePosixPath(*path.parts[1:])
        if not relative.parts:
            continue
        unpacked += item.file_size
        if unpacked > max_unpacked_bytes:
            raise ValueError("Module archive exceeds max_unpacked_bytes")
        safe_entries.append((item, relative))
    if not safe_entries:
        raise ValueError("Module archive contains no files")
    temp_root = Path(tempfile.mkdtemp(prefix="module-", dir=str(cache_root)))
    try:
        for item, relative in safe_entries:
            destination = (temp_root / Path(*relative.parts)).resolve()
            if temp_root.resolve() not in destination.parents:
                raise ValueError("Module archive path escapes extraction directory")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as src, destination.open("wb") as dst:
                remaining = item.file_size
                while remaining:
                    chunk = src.read(min(65_536, remaining))
                    if not chunk:
                        raise ValueError("Truncated module archive entry")
                    dst.write(chunk)
                    remaining -= len(chunk)
        (temp_root / ".scanner-module.json").write_text(archive_hash, encoding="utf-8")
        if target.exists():
            import shutil
            shutil.rmtree(target)
        os.replace(temp_root, target)
    except Exception:
        import shutil
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return {"path": str(target), "source": identity, "ref": ref, "sha256": archive_hash, "cached": "false"}
