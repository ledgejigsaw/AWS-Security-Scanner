# Terraform static-analysis contract

## Objective

The HCL provider is an offline static analyser, not a Terraform interpreter. It resolves values only when the source provides enough evidence, preserves provenance, and makes unsupported constructs visible instead of guessing.

## Supported root inputs

For a root module, supported input precedence is:

1. Variable defaults declared in .tf files.
2. terraform.tfvars, if present.
3. *.auto.tfvars files in lexicographic path order.
4. Explicit --var-file PATH values, in command-line order.

The last known literal value wins. HCL and JSON variable files are supported. An explicit variable file must exist and be a regular file. Inputs are scoped to the selected root module; they are not implicitly applied to child modules. Child modules receive values only through their module arguments, with child defaults used when the caller omits an argument.

Example:

    aws-security-scan --source hcl --file ./terraform/environments/prod \
      --var-file ./terraform/environments/prod/region.tfvars \
      --var-file ./secure-inputs/prod-overrides.json \
      --format sarif --output reports/prod.sarif

Variable values from the process environment, Terraform CLI -var, workspaces, remote state, provider plugins and Terraform Cloud are not read. This is deliberate: the scanner must not silently inherit a user's execution environment or imply that it has Terraform's full variable resolution semantics.

## Expression evaluation

The provider supports literal values and a bounded subset of references, including statically resolvable var.name and local.name values and literal module arguments. Locals are resolved in bounded repeated passes so simple chains can be evaluated independent of file order. Cyclic, provider-dependent, function-based, dynamic or otherwise unsupported expressions remain unresolved.

No HCL expression is evaluated as Python, shell or Terraform code. The scanner does not run terraform init, plan, apply, providers or provisioners. It does not fetch Registry or Git modules. Local-module traversal remains bounded and constrained to the scan root and explicitly trusted roots.

## Dependency and provenance model

All direct-child .tf files in a selected root module are loaded together, so file names and directory enumeration order do not define dependency order. Resources retain canonical addresses and source-file paths. The provider builds a deterministic directed dependency graph after resource discovery, resolves unique canonical targets, and emits IAC-HCL-004 for missing/ambiguous targets and IAC-HCL-005 for directed dependency cycles. Existing relationship extraction records supported resource references separately from resolved scalar values.

A relationship edge does not imply that the target's provider-computed attributes are known. Data sources are not queried, and resource references are not treated as concrete values unless the static evaluator can prove a supported literal value. Unknowns must not be interpreted as a secure/pass result.

## Known limitations and next increments

- Terraform CLI/environment variable sources and workspace state are not loaded.
- Type constraints, validation blocks, sensitive flags and nullable semantics are not a full Terraform type system.
- Functions, templates, arithmetic, ternaries, splats, for expressions, count, for_each and dynamic blocks are not generally evaluated.
- Child outputs are not a general-purpose expression engine; module output propagation remains a separate incremental capability.
- Provider-dependent data sources and computed attributes remain unknown.
- Line/column spans are not currently guaranteed by the parser integration.
- External module retrieval is opt-in via `--fetch-external-modules` and currently supports credential-free HTTPS GitHub sources pinned to a full 40-character commit SHA. Every repository must be explicitly allowed with `--module-source-allowlist OWNER/REPOSITORY`; mutable refs, query parameters other than `ref`, registry sources, private authenticated sources and non-GitHub hosts are rejected. Archives are bounded to 25 MiB downloaded, 100 MiB unpacked and 1,000 files, extracted with path/symlink checks, and cached with commit and SHA-256 provenance. The scanner never runs Terraform, Git, providers, provisioners or downloaded scripts. Network access remains disabled by default.

Every supported extension should include positive, negative and unknown-state tests, preserve deterministic output, and run without AWS credentials or Terraform installed.
