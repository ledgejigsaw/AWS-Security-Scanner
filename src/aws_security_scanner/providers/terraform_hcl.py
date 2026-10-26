"""Offline, conservative Terraform HCL resource loading."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import hcl2
from lark.exceptions import LarkError

from aws_security_scanner.models.resource import Resource
from aws_security_scanner.providers.terraform import TerraformProvider
from aws_security_scanner.terraform_dependency_graph import (
    build_dependency_graph,
    dependency_diagnostics,
    resolve_static_resource_attributes,
)


_NON_LITERAL = object()
_RESOURCE_REFERENCE = re.compile(r"\$\{(aws_[^.]+\.[^.]+)\.[^}]+\}")


def _unquote_label(value: str) -> str:
    """Remove parser-preserved quotes around HCL block labels."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value

_EXTERNAL_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")


def _resolve_pinned_github_module(source: str, *, cache_dir: Path, allowlist: list[str] | None, timeout_seconds: int = 15) -> Path:
    """Fetch an allowlisted immutable GitHub module archive without executing it."""
    import hashlib
    import shutil
    import zipfile
    from io import BytesIO
    from pathlib import PurePosixPath
    from urllib.parse import parse_qs, urlsplit
    from urllib.request import HTTPRedirectHandler, Request, build_opener

    value = source[5:] if source.startswith("git::") else source
    if not value.startswith("https://"):
        raise ValueError("Only HTTPS GitHub module sources are supported.")
    base, separator, query = value.partition("?")
    if not separator:
        raise ValueError("External module source must pin ref to a full 40-character commit SHA.")
    params = parse_qs(query, keep_blank_values=True, strict_parsing=True)
    refs = params.get("ref", [])
    if len(refs) != 1 or not _EXTERNAL_COMMIT.fullmatch(refs[0]) or set(params) != {"ref"}:
        raise ValueError("External module source must use only ref=<full 40-character commit SHA>.")
    path = base[len("https://"):]
    if not path.startswith("github.com/") or "@" in path or "#" in path:
        raise ValueError("Only credential-free github.com HTTPS sources are supported.")
    repo_path, marker, subdirectory = path[len("github.com/"):].partition("//")
    pieces = repo_path.strip("/").split("/")
    if len(pieces) != 2 or not all(pieces):
        raise ValueError("GitHub source must identify exactly one owner and repository.")
    owner, repository = pieces
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repository):
        raise ValueError("GitHub owner/repository contains unsupported characters.")
    if marker:
        subparts = PurePosixPath(subdirectory).parts
        if not subdirectory or subdirectory.startswith("/") or any(part in {"", ".", ".."} for part in subparts):
            raise ValueError("GitHub module subdirectory must be a safe relative path.")
        subdirectory = "/".join(subparts)
    else:
        subdirectory = ""
    identity = f"{owner}/{repository}".lower()
    allowed = {str(item).strip().lower() for item in (allowlist or []) if str(item).strip()}
    if not allowed:
        raise ValueError("External module fetching requires at least one --module-source-allowlist OWNER/REPOSITORY entry.")
    if identity not in allowed:
        raise ValueError(f"External module source {identity!r} is not in the explicit allowlist.")
    cache_dir = cache_dir.expanduser().resolve()
    key = hashlib.sha256(f"{identity}@{refs[0].lower()}".encode()).hexdigest()
    target = (cache_dir / key).resolve()
    if not target.is_relative_to(cache_dir):
        raise ValueError("External module cache path escaped the configured cache directory.")
    module_dir = target / subdirectory if subdirectory else target
    manifest_path = target / ".aws-security-scanner-module.json"
    if manifest_path.is_file() and module_dir.is_dir() and any(module_dir.glob("*.tf")):
        return module_dir
    request = Request(f"https://codeload.github.com/{owner}/{repository}/zip/{refs[0].lower()}", headers={"User-Agent": "aws-security-scanner/terraform-module-fetch"})

    class _CodeloadRedirectsOnly(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, new_url):
            redirected = urlsplit(new_url)
            if redirected.scheme != "https" or redirected.hostname != "codeload.github.com":
                raise ValueError("Module download redirect left the codeload.github.com HTTPS origin.")
            return super().redirect_request(request, fp, code, message, headers, new_url)

    opener = build_opener(_CodeloadRedirectsOnly())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "codeload.github.com":
                raise ValueError("Module download redirected outside codeload.github.com HTTPS.")
            chunks, total = [], 0
            while True:
                chunk = response.read(min(1024 * 1024, 25 * 1024 * 1024 + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 25 * 1024 * 1024:
                    raise ValueError("External module archive exceeds the 25 MiB download limit.")
    except ValueError:
        raise
    except Exception as error:
        raise ValueError(f"Unable to fetch pinned GitHub module ({type(error).__name__}).") from error
    archive = b"".join(chunks)
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    staging = target.with_name(target.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(BytesIO(archive)) as zipped:
            members = zipped.infolist()
            if len(members) > 1000:
                raise ValueError("External module archive exceeds the 1,000-file limit.")
            unpacked, roots = 0, set()
            for member in members:
                member_path = PurePosixPath(member.filename)
                if member_path.is_absolute() or any(part in {"", ".", ".."} for part in member_path.parts):
                    raise ValueError("External module archive contains an unsafe path.")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("External module archive contains a symbolic link.")
                unpacked += member.file_size
                if unpacked > 100 * 1024 * 1024:
                    raise ValueError("External module archive exceeds the 100 MiB unpacked limit.")
                if member_path.parts:
                    roots.add(member_path.parts[0])
            if len(roots) != 1:
                raise ValueError("External module archive must contain exactly one repository root.")
            for member in members:
                relative = PurePosixPath(member.filename)
                destination = (staging / Path(*relative.parts)).resolve()
                if not destination.is_relative_to(staging.resolve()):
                    raise ValueError("External module archive path escaped extraction directory.")
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with zipped.open(member) as src, destination.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
        roots = list(staging.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError("External module archive has an unexpected root layout.")
        if target.exists():
            shutil.rmtree(target)
        shutil.move(str(roots[0]), str(target))
        manifest = {"schema_version": "1.0.0", "source": identity, "commit": refs[0].lower(), "subdirectory": subdirectory, "archive_sha256": archive_sha256, "network_origin": "https://codeload.github.com"}
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    except Exception as error:
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(error, ValueError):
            raise
        raise ValueError(f"Unable to safely unpack pinned GitHub module ({type(error).__name__}).") from error
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    if not module_dir.is_dir() or not any(module_dir.glob("*.tf")):
        raise ValueError("Pinned archive does not contain Terraform files at the requested module path.")
    return module_dir


class TerraformHCLProvider:
    """Parse Terraform HCL and expand bounded local modules without running Terraform."""

    def __init__(self, hcl_file: str | Path, module_roots: list[str | Path] | None = None, var_files: list[str | Path] | None = None, *, fetch_external_modules: bool = False, module_cache: str | Path | None = None, module_source_allowlist: list[str] | None = None):
        self.hcl_file = Path(hcl_file)
        self.fetch_external_modules = bool(fetch_external_modules)
        self.module_cache = Path(module_cache or Path.home() / ".cache" / "aws-security-scanner" / "terraform-modules")
        self.module_source_allowlist = list(module_source_allowlist or [])
        self.module_roots = tuple(Path(root).resolve() for root in (module_roots or []))
        self.var_files = tuple(Path(path).resolve() for path in (var_files or []))
        self.dependency_graph = None
        for root in self.module_roots:
            if not root.is_dir():
                raise ValueError(f"Trusted Terraform module root is not an existing directory: '{root}'.")
        for path in self.var_files:
            if not path.is_file():
                raise ValueError(f"Terraform variable file does not exist or is not a file: '{path}'.")

    def discover(self) -> list[Resource]:
        """Discover HCL resources and expand safe local child modules."""
        if not self.hcl_file.exists():
            raise ValueError(f"Terraform HCL path does not exist: '{self.hcl_file}'")
        if self.hcl_file.is_dir():
            module_dir = self.hcl_file.resolve()
            files = self._module_files(module_dir)
            if not files:
                raise ValueError(
                    f"No Terraform HCL files (*.tf) found directly in module directory '{self.hcl_file}'."
                )
            scan_root = module_dir
        else:
            module_dir = self.hcl_file.resolve().parent
            files = [self.hcl_file.resolve()]
            scan_root = module_dir
        resources = self._discover_module(
            module_dir=module_dir, files=files, scan_root=scan_root,
            address_prefix="", input_values={}, active_stack=(), depth=0,
        )
        TerraformProvider(self.hcl_file)._resolve_relationships(resources)
        known_addresses = {item.source_address for item in resources if item.source_address}
        for resource in resources:
            if not resource.source_address or not resource.source_address.startswith("module.") or not resource.relationships:
                continue
            parent_prefix = ".".join(resource.source_address.split(".")[:-2])
            for key, target in list(resource.relationships.items()):
                qualified = f"{parent_prefix}.{target}"
                if qualified in known_addresses:
                    resource.relationships[key] = qualified
        seen: set[tuple[str, str]] = set()
        unique: list[Resource] = []
        for resource in resources:
            identity = (resource.resource_type, resource.source_address or resource.resource_id)
            if identity not in seen:
                seen.add(identity)
                unique.append(resource)
        # Construct and validate the graph only after all files and permitted
        # local modules have been discovered, so file order cannot affect edges.
        self.static_reference_resolution = resolve_static_resource_attributes(unique)
        self.dependency_graph = build_dependency_graph(unique)
        unique.extend(dependency_diagnostics(self.dependency_graph, unique))
        return unique

    @staticmethod
    def _is_within(path: Path, root: Path) -> bool:
        """Return whether a canonical path is inside an allowed root."""
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            return False
        return True

    @staticmethod
    def _module_files(module_dir: Path) -> list[Path]:
        """List direct-child HCL files only; nested directories need explicit module sources."""
        return sorted(path.resolve() for path in module_dir.glob("*.tf") if path.is_file())

    def _load_hcl(self, path: Path) -> dict[str, Any]:
        try:
            with path.open(encoding="utf-8") as file:
                data = hcl2.load(file)
        except (OSError, ValueError, LarkError) as error:
            raise ValueError(f"Unable to parse Terraform HCL file '{path}': {error}") from error
        if not isinstance(data, dict):
            raise ValueError(f"Terraform HCL root in '{path}' must be an object.")
        return data

    def _discover_module(
        self, *, module_dir: Path, files: list[Path], scan_root: Path,
        address_prefix: str, input_values: dict[str, Any],
        active_stack: tuple[Path, ...], depth: int,
    ) -> list[Resource]:
        max_depth = 8
        module_dir = module_dir.resolve()
        if module_dir in active_stack:
            raise ValueError(f"Terraform local module cycle detected at '{module_dir}'.")
        if depth > max_depth:
            raise ValueError(f"Terraform local module depth exceeds {max_depth} at '{module_dir}'.")

        variables = self._collect_variable_defaults(files)
        # Root input files override defaults; child module arguments are applied last.
        if depth == 0:
            variables.update(self._load_root_variable_values(module_dir))
        variables.update(input_values)
        variables.update(self._collect_local_values(files, variables))
        resources: list[Resource] = []
        module_calls: list[tuple[str, dict[str, Any], Path]] = []
        for path in files:
            data = self._load_hcl(path)
            resources.extend(self._discover_file(path, variables=variables, address_prefix=address_prefix))
            for block in data.get("module", []) if isinstance(data.get("module", []), list) else []:
                if isinstance(block, dict):
                    for raw_name, attrs in block.items():
                        if isinstance(attrs, dict):
                            module_calls.append((_unquote_label(raw_name), attrs, path))

        for name, attrs, declaring_file in module_calls:
            local = f"module.{name}"
            address = f"{address_prefix}.{local}" if address_prefix else local
            source = self._literal_value(attrs.get("source"))
            if "count" in attrs or "for_each" in attrs:
                self._set_module_diagnostic(
                    resources, address, declaring_file,
                    "Module count/for_each changes module cardinality and is not statically expanded.",
                    source=source if isinstance(source, str) else None,
                )
                continue
            external_module = not (isinstance(source, str) and source.startswith(("./", "../")))
            if external_module:
                if not self.fetch_external_modules:
                    self._set_module_diagnostic(
                        resources, address, declaring_file,
                        "External module source was not fetched. Use --fetch-external-modules with a pinned GitHub commit and an explicit --module-source-allowlist entry to opt in.",
                        source=source if isinstance(source, str) else None,
                    )
                    continue
                try:
                    child_dir = _resolve_pinned_github_module(
                        source if isinstance(source, str) else "",
                        cache_dir=self.module_cache,
                        allowlist=self.module_source_allowlist,
                    )
                except (ValueError, OSError) as error:
                    self._set_module_diagnostic(
                        resources, address, declaring_file,
                        f"External module was not expanded: {error}",
                        source=source if isinstance(source, str) else None,
                    )
                    continue
            else:
                child_dir = (declaring_file.parent / source).resolve()
                allowed_roots = (scan_root.resolve(), *self.module_roots)
                if not any(self._is_within(child_dir, allowed_root) for allowed_root in allowed_roots):
                    self._set_module_diagnostic(resources, address, declaring_file,
                        "The local module source resolves outside the selected scan root and all explicitly trusted module roots; it was not followed.", source=source)
                    continue
            if child_dir in (*active_stack, module_dir):
                self._set_module_diagnostic(resources, address, declaring_file,
                    "A local module cycle was detected; expansion stopped at this call.", source=source)
                continue
            if depth >= max_depth:
                self._set_module_diagnostic(resources, address, declaring_file,
                    f"The local module expansion depth limit ({max_depth}) was reached.", source=source)
                continue
            if not child_dir.is_dir():
                self._set_module_diagnostic(resources, address, declaring_file,
                    "The local module source directory does not exist.", source=source)
                continue
            child_files = self._module_files(child_dir)
            if not child_files:
                self._set_module_diagnostic(resources, address, declaring_file,
                    "The local module directory contains no top-level .tf files.", source=source)
                continue

            child_inputs: dict[str, Any] = {}
            for raw_key, raw_value in attrs.items():
                key = _unquote_label(str(raw_key))
                if key in {"source", "version", "providers", "depends_on", "count", "for_each", "__is_block__"}:
                    continue
                normalized = self._normalise_nested_blocks({"value": raw_value}).get("value")
                substituted = self._substitute_variables(normalized, variables)
                value = self._literal_value(substituted)
                if value is not _NON_LITERAL and not self._unresolved_expressions(substituted):
                    child_inputs[key] = value
                else:
                    # Preserve unknown caller expressions so they override child defaults
                    # and remain visible as unresolved in the child resources.
                    child_inputs[key] = raw_value

            resources = [resource for resource in resources if not (
                resource.source_address == address
                and resource.attributes.get("hcl_diagnostic") == "module_not_expanded"
            )]
            try:
                expanded = self._discover_module(
                    module_dir=child_dir, files=child_files, scan_root=scan_root,
                    address_prefix=address, input_values=child_inputs,
                    active_stack=(*active_stack, module_dir), depth=depth + 1,
                )
            except ValueError as error:
                self._set_module_diagnostic(resources, address, declaring_file,
                    f"Local module expansion failed: {error}", source=source)
                continue
            resources.extend(expanded)
        return resources

    def _collect_variable_defaults(self, files: list[Path]) -> dict[str, Any]:
        defaults: dict[str, Any] = {}
        for path in files:
            data = self._load_hcl(path)
            blocks = data.get("variable", [])
            if not isinstance(blocks, list):
                continue
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                for raw_name, attrs in block.items():
                    if isinstance(attrs, dict) and "default" in attrs:
                        value = self._literal_value(attrs["default"])
                        if value is not _NON_LITERAL:
                            defaults[_unquote_label(raw_name)] = value
        return defaults

    def _load_root_variable_values(self, root: Path) -> dict[str, Any]:
        """Load supported root variable files in deterministic precedence order."""
        paths: list[Path] = []
        standard = root / "terraform.tfvars"
        if standard.is_file():
            paths.append(standard)
        paths.extend(sorted(path for path in root.glob("*.auto.tfvars") if path.is_file()))
        paths.extend(self.var_files)
        resolved: dict[str, Any] = {}
        for path in paths:
            try:
                if path.suffix.lower() == ".json":
                    with path.open(encoding="utf-8") as handle:
                        values = json.load(handle)
                else:
                    with path.open(encoding="utf-8") as handle:
                        values = hcl2.load(handle)
            except (OSError, ValueError, LarkError, json.JSONDecodeError) as error:
                raise ValueError(f"Unable to parse Terraform variable file '{path}': {error}") from error
            if not isinstance(values, dict):
                raise ValueError(f"Terraform variable file '{path}' must contain an object.")
            for raw_name, raw_value in values.items():
                name = _unquote_label(str(raw_name))
                normalized = self._normalise_nested_blocks({"value": raw_value}).get("value")
                literal = self._literal_value(normalized)
                if literal is not _NON_LITERAL:
                    resolved[name] = literal
        return resolved

    def _collect_local_values(self, files: list[Path], variables: dict[str, Any]) -> dict[str, Any]:
        """Resolve a bounded subset of local values without evaluating arbitrary HCL."""
        definitions: dict[str, Any] = {}
        for path in files:
            data = self._load_hcl(path)
            blocks = data.get("locals", [])
            if isinstance(blocks, dict):
                blocks = [blocks]
            if isinstance(blocks, list):
                for block in blocks:
                    if isinstance(block, dict):
                        for raw_name, raw_value in block.items():
                            definitions[_unquote_label(str(raw_name))] = raw_value
        resolved: dict[str, Any] = {}
        for _ in range(min(len(definitions) + 1, 32)):
            changed = False
            scope = dict(variables)
            scope.update({f"local.{name}": value for name, value in resolved.items()})
            for name, raw_value in definitions.items():
                if name in resolved:
                    continue
                normalized = self._normalise_nested_blocks({"value": raw_value}).get("value")
                candidate = self._substitute_variables(normalized, scope)
                if self._unresolved_expressions(candidate):
                    continue
                literal = self._literal_value(candidate)
                if literal is not _NON_LITERAL:
                    resolved[name] = literal
                    changed = True
            if not changed:
                break
        return {f"local.{name}": value for name, value in resolved.items()}

    def _literal_value(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1]
        if isinstance(value, str):
            if chr(36) + "{" in value or re.search(r"\b(?:var|local|module)\.[A-Za-z0-9_-]+", value):
                return _NON_LITERAL
        if isinstance(value, list):
            items = [self._literal_value(item) for item in value]
            return _NON_LITERAL if any(item is _NON_LITERAL for item in items) else items
        if isinstance(value, dict):
            items = {key: self._literal_value(item) for key, item in value.items()}
            return _NON_LITERAL if any(item is _NON_LITERAL for item in items.values()) else items
        return value

    def _set_module_diagnostic(
        self, resources: list[Resource], address: str, source_file: Path,
        reason: str, *, source: str | None = None,
    ) -> None:
        for resource in resources:
            if resource.source_address == address and resource.attributes.get("hcl_diagnostic") == "module_not_expanded":
                resource.attributes["hcl_diagnostic_reason"] = reason
                if source is not None:
                    resource.attributes["module_source"] = source
                return
        attrs: dict[str, Any] = {"hcl_diagnostic": "module_not_expanded", "hcl_diagnostic_reason": reason}
        if source is not None:
            attrs["module_source"] = source
        resources.append(Resource(
            resource_type="terraform_hcl_unsupported", resource_id=address,
            attributes=attrs, source="terraform", source_file=str(source_file), source_address=address,
        ))

    def _discover_file(
        self, path: Path, *, variables: dict[str, Any] | None = None, address_prefix: str = "",
    ) -> list[Resource]:
        data = self._load_hcl(path)
        resources: list[Resource] = []
        blocks = data.get("resource", [])
        if isinstance(blocks, dict):
            for resource_type, instances in blocks.items():
                if isinstance(instances, dict):
                    for name, attrs in instances.items():
                        resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attrs, path, variables or {}, address_prefix))
        elif isinstance(blocks, list):
            for block in blocks:
                if isinstance(block, dict):
                    for resource_type, instances in block.items():
                        if isinstance(instances, dict):
                            for name, attrs in instances.items():
                                resources.append(self._make_resource(_unquote_label(resource_type), _unquote_label(name), attrs, path, variables or {}, address_prefix))

        for block in data.get("data", []) if isinstance(data.get("data", []), list) else []:
            if isinstance(block, dict):
                for data_type, instances in block.items():
                    if isinstance(instances, dict):
                        for data_name in instances:
                            addr = f"data.{_unquote_label(data_type)}.{_unquote_label(data_name)}"
                            full = f"{address_prefix}.{addr}" if address_prefix else addr
                            resources.append(Resource(
                                resource_type="terraform_hcl_unsupported", resource_id=full,
                                attributes={"hcl_diagnostic": "data_source_not_evaluated"},
                                source="terraform", source_file=str(path), source_address=full,
                            ))

        for block in data.get("module", []) if isinstance(data.get("module", []), list) else []:
            if isinstance(block, dict):
                for module_name in block:
                    addr = f"module.{_unquote_label(module_name)}"
                    full = f"{address_prefix}.{addr}" if address_prefix else addr
                    resources.append(Resource(
                        resource_type="terraform_hcl_unsupported", resource_id=full,
                        attributes={"hcl_diagnostic": "module_not_expanded"},
                        source="terraform", source_file=str(path), source_address=full,
                    ))
        return resources

    def _make_resource(self, resource_type: str, name: str, raw_attributes: Any, source_file: Path | None = None, variables: dict[str, Any] | None = None, address_prefix: str = "") -> Resource:
        attributes = self._normalise_nested_blocks(raw_attributes if isinstance(raw_attributes, dict) else {})
        attributes = self._substitute_variables(attributes, variables or {})
        unresolved = self._unresolved_expressions(attributes)
        if unresolved:
            attributes = dict(attributes)
            attributes["hcl_unresolved_expressions"] = unresolved
        return Resource(
            resource_type=resource_type,
            resource_id=f"{address_prefix}.{resource_type}.{name}" if address_prefix else name,
            attributes=attributes,
            source="terraform",
            region=attributes.get("region"),
            source_file=str(source_file or self.hcl_file),
            source_address=f"{address_prefix}.{resource_type}.{name}" if address_prefix else f"{resource_type}.{name}",
        )

    def _normalise_nested_blocks(self, attributes: dict[str, Any]) -> dict[str, Any]:
        """Flatten known singleton HCL blocks into the JSON-like rule model."""
        result: dict[str, Any] = {}
        block_names = {
            "versioning_configuration",
            "rule",
            "server_side_encryption_configuration",
            "public_access_block",
            "logging",
            "lifecycle_rule",
        }
        for key, value in attributes.items():
            # python-hcl2 preserves quoted literal strings and adds this marker
            # to nested block dictionaries; neither belongs in normalized attrs.
            if key == "__is_block__":
                continue
            if isinstance(value, str) and len(value) >= 2 and value[0] == value[-1] == '"':
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
            if key in block_names and isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                result[key] = self._normalise_nested_blocks(value[0])
            elif isinstance(value, dict):
                result[key] = self._normalise_nested_blocks(value)
            elif isinstance(value, list):
                result[key] = [
                    self._normalise_nested_blocks(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    def _substitute_variables(self, value: Any, variables: dict[str, Any]) -> Any:
        """Substitute only statically known variable references."""
        pattern = re.compile(r"\x24\{(var|local)\.([A-Za-z0-9_-]+)\}|(?<![A-Za-z0-9_])(var|local)\.([A-Za-z0-9_-]+)(?![A-Za-z0-9_])")
        if isinstance(value, dict):
            return {key: self._substitute_variables(item, variables) for key, item in value.items()}
        if isinstance(value, list):
            return [self._substitute_variables(item, variables) for item in value]
        if not isinstance(value, str):
            return value
        full = pattern.fullmatch(value)
        if full:
            scope = full.group(1) or full.group(3)
            name = full.group(2) or full.group(4)
            key = f"local.{name}" if scope == "local" else name
            return variables.get(key, value)
        def replace(match):
            scope = match.group(1) or match.group(3)
            name = match.group(2) or match.group(4)
            key = f"local.{name}" if scope == "local" else name
            replacement = variables.get(key)
            if replacement is None or isinstance(replacement, (dict, list)):
                return match.group(0)
            return str(replacement)
        return pattern.sub(replace, value)

    def _unresolved_expressions(self, value: Any, path: str = "") -> list[str]:
        unresolved: list[str] = []
        if isinstance(value, dict):
            for key, nested in value.items():
                # count/for_each are expressions that can change resource cardinality.
                child_path = f"{path}.{key}" if path else str(key)
                if key in {"count", "for_each", "dynamic"}:
                    unresolved.append(f"{child_path}: {nested!r}")
                    continue
                unresolved.extend(self._unresolved_expressions(nested, child_path))
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                unresolved.extend(self._unresolved_expressions(nested, f"{path}[{index}]"))
        elif isinstance(value, str):
            if chr(36) + "{" in value:
                references = list(_RESOURCE_REFERENCE.finditer(value))
                remainder = _RESOURCE_REFERENCE.sub("", value)
                if not references or (chr(36) + "{") in remainder:
                    unresolved.append(f"{path}: {value}")
            elif re.search(r"\b(?:var|local|module)\.[A-Za-z0-9_-]+", value):
                unresolved.append(f"{path}: {value}")
        return unresolved
