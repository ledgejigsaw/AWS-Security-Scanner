# Complementary AWS security tooling review

**Reviewed:** 16 October 2026  
**Purpose:** Select complementary capabilities without importing an entire external scanner or duplicating existing findings.

This is a point-in-time repository review, not a guarantee of future maintenance, licence status or compatibility. Recheck the upstream release history and licence before adding any dependency.

## Candidate comparison

| Candidate | Primary value | Overlap with this scanner | Integration cost / risk | Decision |
|---|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Broad IaC misconfiguration, secrets and vulnerability scanning; supports Terraform HCL, JSON and plan formats | High for Terraform misconfiguration; broader for secrets and dependency vulnerabilities | Separate binary/runtime, database updates and network/cache considerations; avoid making CI depend on an online database for deterministic tests | **Recommended optional CI companion**, not a runtime library. Run it as a separate job and keep its report provenance distinct |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC security checks across Terraform, CloudFormation, Kubernetes and related formats | High for IaC checks, with useful resource-graph analysis | Large Python dependency footprint and overlapping findings; mapping and deduplication needed if results are imported | **Alternative to evaluate alongside Trivy**, not both as mandatory dependencies |
| [Prowler](https://github.com/prowler-cloud/prowler) | Broad cloud posture and compliance assessments across AWS and other providers | High for live AWS posture and compliance coverage | Large scope, its own identity/permission model and substantial overlap; imported results require source identity and severity mapping | Use as an external comparison/reference, not embedded into the scanner |
| [Parliament](https://github.com/duo-labs/parliament) | Static IAM policy linting: policy structure, action/resource matching and common policy errors | Partial overlap with the scanner's custom IAM heuristics | Python dependency and IAM definition freshness; findings need clear provenance; upstream maintenance must be rechecked before adoption | **Do not add yet**. First compare it against current IAM tests and establish measurable additional detections |
| [AWS Network Access Analyzer](https://docs.aws.amazon.com/vpc/latest/network-access-analyzer/what-is-network-access-analyzer.html) | AWS-native network reachability analysis against defined network-access requirements | Complements current subnet, route, NACL and security-group checks | Requires AWS API support, explicit analysis requirements and additional read-only permissions; not equivalent to a static relationship graph | Future live-account enhancement; not a fixture-only drop-in replacement |
| [CloudMapper](https://github.com/duo-labs/cloudmapper) / [Cartography](https://github.com/cartography-cncf/cartography) | Architecture inventory and relationship visualisation | Overlaps with the current resource graph and conservative relationship extraction | Separate data models, deployment/collection footprint and potential expansion of collected data | Keep the current minimal graph; only adopt a focused interoperability format if it improves evidence-backed relationships |

## Licensing and maintenance notes

- The upstream [AWS security-tools catalogue](https://github.com/toniblyx/my-arsenal-of-aws-security-tools) is an index of independent tools, not a single library or licence. Each candidate must be checked independently.
- Trivy's upstream repository publishes frequent tagged releases; its release page showed v0.76.0 dated 14 October 2026 at review time ([releases](https://github.com/aquasecurity/trivy/releases)).
- Checkov's upstream repository is Apache-2.0 licensed and had a 3.3.21 release dated 30 September 2026 at review time ([releases](https://github.com/bridgecrewio/checkov/releases)).
- Parliament's upstream repository declares BSD-3-Clause and describes itself as an IAM policy linting library ([repository](https://github.com/duo-labs/parliament)). Its last commit/release cadence should be checked directly before a dependency decision; do not infer current maintenance from popularity.
- Prowler's licence, current release cadence and support matrix must be revalidated from its upstream repository at the time of adoption ([repository](https://github.com/prowler-cloud/prowler)).

Licence identifiers above are initial screening information, not legal advice. Review the exact licence file, transitive dependencies, notices and intended distribution model before adding a dependency or copying any code/rules.

## Decisions and next actions

1. **No mandatory external runtime dependency.** The scanner should remain installable, offline-testable and predictable without another security engine.
2. **Prefer separate CI execution for IaC breadth.** Prototype Trivy first against the same safe/insecure Terraform fixtures and compare outputs with the native scanner. Do not make the unit-test suite download databases or require network access.
3. **Do not ingest external findings until provenance is designed.** Any future importer needs stable source/check IDs, source versions, file/line/resource identity, severity mapping, deduplication rules and explicit opt-in.
4. **Keep native AWS integrations focused.** The scanner's own read-only rules and optional native findings are easier to test than wrapping Prowler or another full account scanner.
5. **Compare IAM linting empirically.** If Parliament is reconsidered, create a fixture corpus of policies the current scanner accepts/rejects, then measure unique useful detections and false positives before adding it.
6. **Preserve scope boundaries.** Do not incorporate offensive exploitation, remediation/write operations, secrets retrieval or object-content collection into this posture scanner.

## Evidence and limitations

The upstream repositories and documentation linked above were checked on 16 October 2026. Release cadence is only a maintenance signal, not proof of quality or security. This review does not run the tools, establish full licence compatibility, or prove that external findings would be correct for a particular AWS account.
