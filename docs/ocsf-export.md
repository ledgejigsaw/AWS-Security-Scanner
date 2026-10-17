# OCSF finding export

The `--format ocsf` option writes a JSON array of OCSF 1.7.0 **Detection Finding** events. The implementation uses class UID `2004`; it does not use the deprecated Security Finding class UID `2001`.

```bash
aws-security-scan --source terraform --file terraform.json --format ocsf --output reports/scan.ocsf.json
```

## Mapping

- Canonical finding check ID and title map to `finding_info.analytic`.
- Finding title/description map to `finding_info` and `message`.
- Scanner severity maps to OCSF severity IDs: Informational 1, Low 2, Medium 3, High 4, Critical 5.
- Resource identity is emitted under `resources`; region and account ID are added to the cloud object only when known.
- Source finding identity, evidence, remediation, risk metadata and IaC source attribution are preserved under `unmapped` rather than being assigned invented OCSF semantics.
- A stable SHA-256 identifier is derived from the scanner/source finding identity fields.

OCSF requires an event timestamp. The exporter uses a valid timezone-aware source observation timestamp when available; otherwise it uses the export-generation time. Therefore exports without source timestamps are not byte-for-byte deterministic across separate invocations, although event order and finding UIDs are stable for the same input.

The exporter does not claim full conformance against every optional OCSF profile or schema extension. Validate against the OCSF schema version used by your downstream platform before production ingestion. See the [official OCSF schema repository](https://github.com/ocsf/ocsf-schema), [Detection Finding schema](https://github.com/ocsf/ocsf-schema/blob/main/events/findings/finding.json) and [OCSF schema guidance](https://github.com/ocsf/ocsf-docs/blob/main/faqs/schema-faq.md).

No third-party scanner code is copied into this exporter.
