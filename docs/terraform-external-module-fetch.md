# Opt-in external Terraform module fetching

External module fetching is disabled by default. The initial downloader supports only root modules hosted in explicitly allowlisted public GitHub repositories and pinned to a full commit SHA. Registry sources remain validation-only. It downloads an archive over HTTPS, enforces timeout/download/file/unpacked-size bounds, rejects traversal and symbolic links, extracts without invoking Git or Terraform, and caches by source identity and immutable commit. The returned SHA-256 records the exact archive bytes used.

Example usage from Python:

```python
from aws_security_scanner.terraform_external_module_fetch import fetch_pinned_github_module

result = fetch_pinned_github_module(
    "git::https://github.com/example/security-module.git?ref=0123456789abcdef0123456789abcdef01234567",
    ".cache/terraform-modules",
    enabled=True,
    allowed_repositories=("example/security-module",),
)
```

Replace the example repository and SHA with a real, reviewed immutable source. The example is illustrative; it is not fetched during a normal scan. Do not allowlist arbitrary repositories. Private-module credentials and subdirectory module sources are intentionally unsupported in this first slice. Downloaded files are source text only: this helper does not evaluate expressions, install providers, execute provisioners, or run module scripts. The caller must feed the extracted directory through the existing local-module analysis and mark analysis incomplete if a module is skipped or fails to resolve.

The downloader uses bounded archive extraction, but it is still an opt-in network trust boundary. Review source, limits, allowlist and cache location before enabling it. No test or CI run is performed by this change.
