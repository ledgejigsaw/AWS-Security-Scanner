# Provider-neutral architecture: contract and migration boundary

**Status:** Design increment; not a claim of multi-cloud support.  
**Reviewed:** 16 October 2026  
**Related issue:** [#58](https://github.com/ledgejigsaw/AWS-Security-Scanner/issues/58)

## Current baseline

The scanner currently has source-specific discovery implementations for fixtures, Terraform JSON, partial Terraform HCL and AWS APIs. AWS discovery is orchestrated in the CLI through a service-to-discovery mapping. Normalised resources feed a common rule engine, findings model, policy layer and JSON/HTML/SARIF reporting.

The shared Resource model already carries resource type, resource ID, attributes, source, region, relationships and optional account ID. The current model is useful for the AWS scanner but does not yet define an explicit provider-neutral discovery contract. It also does not currently model Azure subscription/GCP project identifiers or a first-class discovery completeness state.

## Proposed provider contract

The first abstraction should be deliberately small. It should describe discovery outcomes, not force each cloud provider to expose identical APIs.

A future typed interface should provide:

- **provider_id:** stable identifier such as aws, azure or gcp.
- **discover(scope):** return normalised resources and structured discovery issues for the explicitly requested scope.
- **supported_resource_types:** documented provider-specific resource types, not an assertion of feature parity.
- **DiscoveryIssue:** provider, service/resource scope, operation, category (access denied, unsupported, unavailable, partial or unexpected), safe message and whether the affected scope is incomplete.
- **Explicit identity metadata:** provider, AWS account ID, Azure subscription ID or GCP project ID, and region/location where the service has one.
- No credentials, secret values, raw object contents or full sensitive policy documents in shared identity/evidence fields.

The contract should keep provider-specific SDK clients and API calls inside providers/<provider>.py. Normalisation should map provider payloads to resources; rules should consume normalised resource semantics and must not instantiate SDK clients.

## Unknown and incomplete discovery semantics

A missing resource and an unobservable resource are different states. The future contract must preserve that distinction:

- A successful empty list is an observed absence only when the API semantics support that conclusion.
- Access denied, unsupported APIs, disabled services, incomplete pagination and transient failures must not become an empty successful result.
- A partial scan must be marked incomplete at the affected scope; a report must not imply that unobserved resources passed their checks.
- Provider-specific rules remain provider-specific unless semantic equivalence and evidence requirements are demonstrated.
- Discovery errors should be reported without leaking request headers, credentials or sensitive payloads.

The existing AWS behaviour is the regression baseline. This design note does not change current error handling or report schemas by itself.

## Resource and finding identity

Resource/finding identity must avoid collisions across providers and accounts. Where scope exists, identity should include:

provider + account/subscription/project + region/location + resource type + resource ID

A missing scope component should remain explicitly unknown rather than being replaced with a fabricated value. Existing AWS finding IDs and baseline fingerprints must remain compatible unless a versioned migration is proposed and reviewed. Any schema change must preserve JSON, HTML and SARIF output compatibility or explicitly version the affected schema.

## Incremental migration plan

1. Add tests that capture existing AWS registry IDs, representative fixture findings, policy overrides, baseline fingerprints and report schemas.
2. Introduce typed discovery result/error models with backwards-compatible defaults; do not change the CLI flow in the same commit.
3. Define a Protocol for discovery and adapt the existing AWS provider behind it without changing its API-call behaviour.
4. Make the CLI consume the contract while retaining the existing source flags and service selectors.
5. Add provider-aware identity metadata and collision tests across AWS account/region fixtures before changing fingerprints.
6. Add applicability metadata for rules and registry validation; do not mark AWS-specific rules as cross-cloud.
7. Only then consider a minimal Azure or GCP provider in a separate issue/PR, starting with one service and mocked tests.

## Explicit non-goals for this increment

- No Azure/GCP provider is implemented by this document.
- No broad Resource model rewrite or report schema migration.
- No live cloud calls in tests.
- No cloud SDK clients in rule functions.
- No claim of provider-neutral detection parity.

## Review gate

Before implementing the contract, confirm the proposed error categories, identity fields and backward-compatibility strategy in a focused review. Issue #58 remains open until a typed contract is implemented by AWS and the existing regression suite demonstrates unchanged AWS behaviour.
